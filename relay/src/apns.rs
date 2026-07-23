//! APNs (Apple Push Notification service) client — token-auth flavour.
//!
//! Pizzini's threat model forbids putting any peer information in the
//! push payload. The body is the literal string `"New message"` and
//! nothing else: no sender, no peer-id, no fingerprint, no message
//! bytes. The push is a *wake-up*; the app fetches the actual ciphertext
//! over the relay once it is foregrounded.
//!
//! Why so paranoid: the iOS notification database is plaintext on disk
//! and has been used (Cellebrite / FBI, April 2026, CVE-2026-28950) to
//! recover deleted Signal messages from a seized iPhone. Apple patched
//! the extraction path in 26.4.2 / 18.7.8 but the database itself
//! remains. Anything we put in the payload sits there in cleartext, plus
//! at Apple, plus on the wire to APNs (TLS to Apple, but Apple sees it).
//!
//! Retention hardening (F-PUSH-03): every wake-up also carries the same
//! static `apns-collapse-id`, so a new push *replaces* the previous one
//! in Notification Center instead of stacking. The visible Notification
//! Center therefore shows at most one Pizzini record — the latest —
//! rather than a per-message arrival timeline, which is exactly the
//! metadata a CVE-2026-28950-style forensic pass would otherwise
//! harvest from the visible surface. On patched iOS the replaced record
//! is dropped from the underlying store too; on the pre-fix builds this
//! CVE is about, the store may still retain replaced records (that IS
//! the bug), so the collapse ID bounds the visible timeline but not the
//! forensic one there — see the residual in docs/security-audit. Side
//! effect: while the device is unreachable APNs stores only the newest
//! wake-up per collapse ID, so the app-side badge bump can undercount a
//! burst; the main app resyncs the true count on next launch (see the
//! iOS NotificationService extension). The ID is one static string for
//! every user, so it tells Apple nothing the topic header didn't.
//!
//! Auth: token-based (ES256 JWT, `.p8` provider key). The JWT is cached
//! for 50 minutes — Apple permits up to 60 — and re-signed lazily when
//! it expires.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use tokio::sync::Mutex;

const JWT_TTL_SECS: u64 = 50 * 60;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Static config — derived from env once at startup. `bundle_id` is the
/// `apns-topic` header (must match the iOS app's bundle identifier).
#[derive(Clone)]
pub struct ApnsConfig {
    pub team_id: String,
    pub key_id: String,
    pub bundle_id: String,
    pub key_path: PathBuf,
    pub endpoint: ApnsEndpoint,
}

#[derive(Copy, Clone, Debug)]
pub enum ApnsEndpoint {
    Sandbox,
    Production,
}

impl ApnsEndpoint {
    fn host(self) -> &'static str {
        match self {
            ApnsEndpoint::Sandbox => "https://api.sandbox.push.apple.com",
            ApnsEndpoint::Production => "https://api.push.apple.com",
        }
    }
}

/// F-PUSH-02: how long (seconds) APNs may hold an undelivered wake-up before
/// discarding it. Sent as the `apns-expiration` header (an absolute UNIX
/// time, `now + this`). Without it APNs stores-and-redelivers indefinitely,
/// which (a) re-couples delivery time to the device's reconnect — partly
/// defeating `PUSH_JITTER` — and (b) can fire a "ghost" wake-up for a message
/// the relay's offline queue already dropped on TTL. This MUST stay well
/// below the relay's offline-queue TTL so a push can never outlive the
/// message it nudges for. 5 minutes covers a brief network/Tor reconnect blip
/// while keeping the store-and-forward window small. (A real-device tradeoff
/// — shorter favours privacy, longer favours background deliverability.)
const PUSH_EXPIRATION_SECS: u64 = 300;

/// Absolute `apns-expiration` value for a wake-up sent at `now_secs`.
fn push_expiration_at(now_secs: u64) -> u64 {
    now_secs.saturating_add(PUSH_EXPIRATION_SECS)
}

/// F-PUSH-03: static collapse key shared by every wake-up. MUST stay a
/// single constant — a per-peer or per-message value would hand Apple
/// (and the on-device notification store) a correlation handle the
/// content-free payload was designed to withhold. APNs caps collapse
/// IDs at 64 bytes.
const COLLAPSE_ID: &str = "new-message";

/// The wake-up's static + time-derived request headers, excluding the
/// per-request `apns-topic` (bundle id) and `authorization` (JWT).
/// Extracted from `send_wakeup` — like `wakeup_body()` — so the
/// F-PUSH-02 expiration and F-PUSH-03 collapse-id invariants are
/// compile-coupled to a unit-testable surface instead of living as
/// untested call-site side effects: dropping any entry now fails a
/// whole-value assertion rather than silently reverting behaviour with
/// green CI.
fn wakeup_headers(now_secs: u64) -> [(&'static str, String); 3] {
    [
        ("apns-push-type", "alert".to_string()),
        // F-PUSH-02: bound how long APNs may store-and-redeliver this
        // wake-up so it can't outlive the queued message or re-couple
        // delivery timing to the device's reconnect.
        ("apns-expiration", push_expiration_at(now_secs).to_string()),
        // F-PUSH-03: successive wake-ups replace each other in
        // Notification Center — see the module docs.
        ("apns-collapse-id", COLLAPSE_ID.to_string()),
    ]
}

/// The one and only push payload. Extracted from `send_wakeup` so the
/// "content-free literal" invariant is unit-testable: any field added
/// here must consciously update the pinned test below, the threat
/// model, and CONTRIBUTING.md's threat-model-adjacent UX rules.
fn wakeup_body() -> serde_json::Value {
    // `mutable-content: 1` makes iOS invoke the app's Notification
    // Service Extension before displaying. The extension reads the
    // locally stored unread count from the shared App Group container,
    // increments it, and stamps the right `badge` on the notification.
    // We deliberately do NOT send a `badge` field here — the relay
    // doesn't know (and shouldn't know) the recipient's per-peer unread
    // count, and APNs only accepts absolute values. Letting the device
    // do the math keeps the count out of Apple's logs.
    serde_json::json!({
        "aps": {
            "alert": "New message",
            "sound": "default",
            "mutable-content": 1
        }
    })
}

impl ApnsConfig {
    /// Reads APNS_AUTH_KEY_PATH / APNS_TEAM_ID / APNS_KEY_ID. Returns
    /// `Ok(None)` when none are set (push disabled), and `Err` when the
    /// set is partially specified — that's almost certainly a config
    /// mistake we'd rather surface loudly.
    pub fn from_env() -> Result<Option<Self>, String> {
        let key_path = std::env::var("APNS_AUTH_KEY_PATH").ok();
        let team_id = std::env::var("APNS_TEAM_ID").ok();
        let key_id = std::env::var("APNS_KEY_ID").ok();
        let any = key_path.is_some() || team_id.is_some() || key_id.is_some();
        let all = key_path.is_some() && team_id.is_some() && key_id.is_some();
        if !any {
            return Ok(None);
        }
        if !all {
            return Err(
                "APNs partially configured. Set all of APNS_AUTH_KEY_PATH, \
                 APNS_TEAM_ID, APNS_KEY_ID — or none."
                    .into(),
            );
        }
        // `APNS_ENDPOINT` must be set explicitly once APNs keys are
        // configured. Silently defaulting to Sandbox here means a
        // production/TestFlight build (whose device tokens are bound
        // to one APNs environment) gets `BadDeviceToken` rejections
        // the moment the two sides drift — with no operator-visible
        // signal. Fail closed: an APNs deployment with no explicit
        // environment is a misconfiguration, not a Sandbox default.
        let endpoint = match std::env::var("APNS_ENDPOINT").as_deref() {
            Ok("production") | Ok("prod") => ApnsEndpoint::Production,
            Ok("sandbox") | Ok("dev") => ApnsEndpoint::Sandbox,
            Ok(other) => {
                return Err(format!(
                    "APNS_ENDPOINT={other:?} is not recognised. Set it to \
                     'production' or 'sandbox' explicitly."
                ));
            }
            Err(_) => {
                return Err(
                    "APNs is configured (APNS_AUTH_KEY_PATH / APNS_TEAM_ID / \
                     APNS_KEY_ID set) but APNS_ENDPOINT is unset. Set it to \
                     'production' or 'sandbox' explicitly — the relay will \
                     not guess, because a wrong guess silently breaks every \
                     wake-up push."
                        .into(),
                );
            }
        };
        let bundle_id =
            std::env::var("APNS_TOPIC").unwrap_or_else(|_| "com.bytepotato.pizzini".to_string());
        Ok(Some(Self {
            team_id: team_id.unwrap(),
            key_id: key_id.unwrap(),
            bundle_id,
            key_path: PathBuf::from(key_path.unwrap()),
            endpoint,
        }))
    }
}

#[derive(Clone)]
pub struct ApnsClient {
    cfg: ApnsConfig,
    encoding_key: EncodingKey,
    http: reqwest::Client,
    cached_jwt: Arc<Mutex<Option<CachedJwt>>>,
}

#[derive(Clone)]
struct CachedJwt {
    token: String,
    expires_at: u64,
}

#[derive(Serialize)]
struct Claims {
    iss: String,
    iat: u64,
}

impl ApnsClient {
    pub fn new(cfg: ApnsConfig) -> Result<Self, String> {
        let pem = std::fs::read(&cfg.key_path)
            .map_err(|e| format!("read APNs .p8 at {:?}: {e}", cfg.key_path))?;
        let encoding_key = EncodingKey::from_ec_pem(&pem)
            .map_err(|e| format!("parse APNs .p8 (must be EC PKCS#8 PEM): {e}"))?;
        let http = reqwest::Client::builder()
            .http2_prior_knowledge()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| format!("build reqwest http2 client: {e}"))?;
        Ok(Self {
            cfg,
            encoding_key,
            http,
            cached_jwt: Arc::new(Mutex::new(None)),
        })
    }

    pub fn endpoint(&self) -> ApnsEndpoint {
        self.cfg.endpoint
    }

    /// Sends the canonical "New message" wake-up push. Payload contains
    /// no peer data — see the module docs for why.
    pub async fn send_wakeup(&self, device_token: &[u8]) -> Result<(), String> {
        let jwt = self.current_jwt().await?;
        let token_hex = hex_encode(device_token);
        let url = format!("{}/3/device/{token_hex}", self.cfg.endpoint.host());
        let body = wakeup_body();
        let mut req = self
            .http
            .post(&url)
            .header("apns-topic", &self.cfg.bundle_id)
            .header("authorization", format!("bearer {jwt}"));
        // Fold in the wake-up headers (push-type, F-PUSH-02 expiration,
        // F-PUSH-03 collapse-id) from the shared builder so the
        // production path and the pinned test agree by construction.
        for (name, value) in wakeup_headers(unix_now()) {
            req = req.header(name, value);
        }
        let resp = req
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("apns post: {e}"))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let reason = resp.text().await.unwrap_or_default();
        Err(format!("apns rejected ({status}): {reason}"))
    }

    async fn current_jwt(&self) -> Result<String, String> {
        let now = unix_now();
        {
            let cache = self.cached_jwt.lock().await;
            if let Some(c) = cache.as_ref() {
                // `>=` not `>` — strict comparison races on the boundary
                // second. A stale JWT means a 401 from APNs and an
                // extra round-trip; the keepalive margin is cheap.
                if c.expires_at >= now + 60 {
                    return Ok(c.token.clone());
                }
            }
        }
        let claims = Claims {
            iss: self.cfg.team_id.clone(),
            iat: now,
        };
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.cfg.key_id.clone());
        let token = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|e| format!("sign apns jwt: {e}"))?;
        let cached = CachedJwt {
            token: token.clone(),
            expires_at: now + JWT_TTL_SECS,
        };
        *self.cached_jwt.lock().await = Some(cached);
        Ok(token)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_expiration_is_finite_and_bounded() {
        // F-PUSH-02: the wake-up carries a finite `apns-expiration` (now + a
        // few minutes), never "store indefinitely". It must be a small,
        // bounded window so the push cannot outlive the relay's multi-day
        // offline queue (no ghost wake-ups) and saturates instead of
        // overflowing near u64::MAX.
        let now = 1_760_000_000u64;
        assert_eq!(push_expiration_at(now), now + PUSH_EXPIRATION_SECS);
        // Well under a day, hence far under the offline-queue TTL.
        assert!(PUSH_EXPIRATION_SECS < 24 * 60 * 60);
        // No overflow at the u64 ceiling.
        assert_eq!(push_expiration_at(u64::MAX), u64::MAX);
    }

    #[test]
    fn wakeup_payload_is_the_static_content_free_literal() {
        // F-PUSH-03 regression pin: the push payload is one static,
        // content-free literal. No sender, no peer-id, no preview, no
        // badge, no per-message field of any kind — the iOS
        // notification store retains delivered records (and retained
        // even "deleted" ones on pre-CVE-2026-28950-patch builds), so
        // any dynamic field added here becomes a forensic artifact.
        // Whole-value equality means a new field fails this test and
        // forces a conscious threat-model decision.
        let expected: serde_json::Value = serde_json::json!({
            "aps": {
                "alert": "New message",
                "sound": "default",
                "mutable-content": 1
            }
        });
        assert_eq!(wakeup_body(), expected);
        // Belt and braces against a refactor that keeps these three
        // keys but grows the envelope.
        let body = wakeup_body();
        let top = body.as_object().unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(top["aps"].as_object().unwrap().len(), 3);
    }

    #[test]
    fn wakeup_headers_carry_collapse_id_and_bounded_expiration() {
        // F-PUSH-02 + F-PUSH-03 regression pin. Whole-value equality on
        // the builder the production path folds into every request: if a
        // refactor drops or mutates the collapse-id or expiration
        // header, this fails. The previous is_empty()/len() check could
        // not catch that — it never touched the header path, so deleting
        // the `.header("apns-collapse-id", …)` call kept the const
        // "used" (no dead-code warning) and left CI green while wake-ups
        // silently reverted to stacking one record per message.
        let now = 1_760_000_000u64;
        assert_eq!(
            wakeup_headers(now),
            [
                ("apns-push-type", "alert".to_string()),
                ("apns-expiration", (now + PUSH_EXPIRATION_SECS).to_string()),
                ("apns-collapse-id", "new-message".to_string()),
            ]
        );
        // The collapse id must be a single static value (no per-peer /
        // per-message correlation handle) and fit APNs' 64-byte cap.
        assert!(COLLAPSE_ID.len() <= 64);
    }
}
