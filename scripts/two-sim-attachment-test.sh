#!/usr/bin/env bash
# Two-sim end-to-end test for the chunked-attachment send/receive flow.
#
# Drives a 9.9 MB JPEG from sim A's photo library all the way to sim B's
# chat log, exercising:
#   - PairAndSendUITests phase 1 (dismiss onboarding)
#   - phase 2 (capture own QR → clipboard)  ×2 sides
#   - phase 3 (paste peer QR + add)         ×2 sides
#   - phase 4 (send the attachment, sim A)
#   - phase 5 (verify the row arrived, sim B)
#
# Clipboard handoffs are explicit `xcrun simctl pbpaste / pbcopy` calls
# in this script — UITests can't see across sim boundaries.
#
# Pre-conditions:
#   - both sims booted
#   - app installed on both
#   - relay running on the host (cargo run -p pizzini-relay)
#   - /tmp/test-9.9mb.jpg exists in both sims' photo libraries
#
# Logs each phase's outcome to /tmp/pizzini-screens/two-sim/.

set -euo pipefail

SIM_A="${SIM_A:-6F4CBB51-7DFA-4151-B489-3B80B3C2475C}"   # iPhone 17 Pro (sender)
SIM_B="${SIM_B:-18D04572-924E-477A-8A91-325DBE18EB12}"   # iPhone 16 Pro (receiver)
BUNDLE="com.bytepotato.pizzini"
SCHEME="pizzini"
PROJECT="pizzini/pizzini.xcodeproj"
ARTIFACTS="/tmp/pizzini-screens/two-sim"

mkdir -p "$ARTIFACTS"

run_phase () {
    local sim="$1"; local phase="$2"; local label="$3"
    echo
    echo "=== $label  (sim=$sim, $phase) ==="
    xcodebuild test-without-building \
        -project "$PROJECT" \
        -scheme "$SCHEME" \
        -destination "platform=iOS Simulator,id=$sim" \
        -only-testing "pizziniUITests/PairAndSendUITests/$phase" \
        2>&1 | tail -10
}

extract_artifacts () {
    local sim_label="$1"; local phase_name="$2"
    local xcr
    xcr=$(ls -td /Users/username/Library/Developer/Xcode/DerivedData/pizzini-*/Logs/Test/*.xcresult 2>/dev/null | head -1)
    [[ -n "$xcr" ]] || return 0
    local out="$ARTIFACTS/$sim_label-$phase_name"
    rm -rf "$out"
    xcrun xcresulttool export attachments \
        --path "$xcr" \
        --test-id "PairAndSendUITests/$phase_name()" \
        --output-path "$out" 2>/dev/null || true
}

# Phase 1: dismiss onboarding on both sims (parallel-ish — back to back).
run_phase "$SIM_A" "test_phase1_dismissOnboarding" "A: dismiss onboarding"
run_phase "$SIM_B" "test_phase1_dismissOnboarding" "B: dismiss onboarding"

# Phase 2 + 3 (cross): A copies own QR → B pastes
run_phase "$SIM_A" "test_phase2_copyMyQRToClipboard" "A: copy my QR"
xcrun simctl pbpaste "$SIM_A" > "$ARTIFACTS/qr-A.txt"
echo "captured A's QR: $(head -c 80 "$ARTIFACTS/qr-A.txt")…"
xcrun simctl pbcopy "$SIM_B" < "$ARTIFACTS/qr-A.txt"
run_phase "$SIM_B" "test_phase3_pasteTheirQRAndAdd" "B: paste A's QR + add"

# Phase 2 + 3 (cross): B copies own QR → A pastes
run_phase "$SIM_B" "test_phase2_copyMyQRToClipboard" "B: copy my QR"
xcrun simctl pbpaste "$SIM_B" > "$ARTIFACTS/qr-B.txt"
echo "captured B's QR: $(head -c 80 "$ARTIFACTS/qr-B.txt")…"
xcrun simctl pbcopy "$SIM_A" < "$ARTIFACTS/qr-B.txt"
run_phase "$SIM_A" "test_phase3_pasteTheirQRAndAdd" "A: paste B's QR + add"

# Give both sides a moment to handshake (BUNDLE_REQUEST/RESPONSE +
# TOKEN_ISSUE batches over the relay).
echo "waiting 8s for both-sides handshake..."
sleep 8

# Phase 4: A sends the attachment.
run_phase "$SIM_A" "test_phase4_sendPhotoAttachment" "A: send photo"
extract_artifacts A test_phase4_sendPhotoAttachment

# Phase 5: B verifies the row arrived.
run_phase "$SIM_B" "test_phase5_verifyAttachmentReceived" "B: verify receive"
extract_artifacts B test_phase5_verifyAttachmentReceived

echo
echo "DONE. Artifacts under $ARTIFACTS/"
ls -la "$ARTIFACTS"
