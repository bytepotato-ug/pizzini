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
        let endpoint = match std::env::var("APNS_ENDPOINT").as_deref() {
            Ok("production") | Ok("prod") => ApnsEndpoint::Production,
            _ => ApnsEndpoint::Sandbox,
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
        // `mutable-content: 1` makes iOS invoke our Notification Service
        // Extension before displaying. The extension reads the locally
        // stored unread count from the shared App Group container,
        // increments it, and stamps the right `badge` on the
        // notification. We deliberately do NOT send a `badge` field
        // here — the relay doesn't know (and shouldn't know) the
        // recipient's per-peer unread count, and APNs only accepts
        // absolute values. Letting the device do the math keeps the
        // count out of Apple's logs.
        let body = serde_json::json!({
            "aps": {
                "alert": "New message",
                "sound": "default",
                "mutable-content": 1
            }
        });
        let resp = self
            .http
            .post(&url)
            .header("apns-topic", &self.cfg.bundle_id)
            .header("apns-push-type", "alert")
            .header("authorization", format!("bearer {jwt}"))
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
                if c.expires_at > now + 60 {
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
