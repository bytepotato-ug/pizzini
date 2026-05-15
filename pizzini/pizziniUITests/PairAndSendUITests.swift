import XCTest

/// Orchestrated multi-sim UITests for the end-to-end attachment flow.
/// Each phase is run individually by scripts/two-sim-attachment-test.sh
/// with `xcrun simctl pbcopy` / `pbpaste` carrying the QR strings
/// between sims between phases.
///
/// Each phase calls `dismissOnboardingIfPresent` first because
/// `xcodebuild test-without-building` may reinstall the app on the
/// simulator across phases, blowing away the Keychain-persisted
/// onboardingCompleted flag in the process. The helper is a no-op when
/// onboarding isn't visible, so phases also work when state is preserved.
final class PairAndSendUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    private func dismissOnboardingIfPresent(_ app: XCUIApplication) {
        // Welcome → Continue, Icons → Continue, Notifications →
        // Skip, Biometric → "Use app passcode instead" → set passcode.
        //
        // onboarding no longer offers "Skip — I'll add it
        // later" on the biometric step. The user must enable Face ID
        // or set an app passcode before reaching the home screen.
        // The simulator can't enrol Face ID via UI test, so we go
        // through the passcode path.
        for _ in 0..<3 {
            let cont = app.buttons["Continue"].firstMatch
            if cont.waitForExistence(timeout: 2) {
                cont.tap()
            } else {
                break
            }
        }
        // Notifications step has a "Skip — I'll enable in Settings
        // later" button — that one IS still present (notifications
        // are non-essential, the lock posture is essential).
        let skipNotif = app.buttons["Skip — I'll enable in Settings later"].firstMatch
        if skipNotif.waitForExistence(timeout: 2) {
            skipNotif.tap()
        }
        // Biometric step — fall through to "Use app passcode instead"
        // so the simulator can complete onboarding deterministically.
        let usePasscode = app.buttons["Use app passcode instead"].firstMatch
        if usePasscode.waitForExistence(timeout: 2) {
            usePasscode.tap()
            // PasscodeSetupView sheet appears. Type a test passcode.
            let entryField = app.secureTextFields["New passcode"].firstMatch
            if entryField.waitForExistence(timeout: 2) {
                entryField.tap()
                entryField.typeText("test1234")
            }
            let confirmField = app.secureTextFields["Confirm"].firstMatch
            if confirmField.waitForExistence(timeout: 2) {
                confirmField.tap()
                confirmField.typeText("test1234")
            }
            let save = app.buttons["Save"].firstMatch
            if save.waitForExistence(timeout: 2) {
                save.tap()
            }
        }
    }

    /// Wait for the home screen to be ready (toolbar's add-contact "+"
    /// is the unambiguous marker — present in both empty and non-empty
    /// home states).
    @MainActor
    private func waitForHome(_ app: XCUIApplication, timeout: TimeInterval = 10) {
        let homeMarker = app.buttons["Add contact"].firstMatch
        XCTAssertTrue(
            homeMarker.waitForExistence(timeout: timeout),
            "expected the home screen 'Add contact' toolbar button — onboarding may have stalled",
        )
    }

    // MARK: - Phase 1: dismiss onboarding (clean install)

    @MainActor
    func test_phase1_dismissOnboarding() throws {
        let app = XCUIApplication()
        app.launch()
        dismissOnboardingIfPresent(app)
        waitForHome(app)
    }

    // MARK: - Phase 2: copy MY QR to the system clipboard

    @MainActor
    func test_phase2_copyMyQRToClipboard() throws {
        let app = XCUIApplication()
        app.launch()
        dismissOnboardingIfPresent(app)
        waitForHome(app)
        // Tap the toolbar "Show my QR" — narrow it down to the navbar
        // descendants so we don't match the empty-state button.
        let toolbarQR = app.navigationBars.buttons["Show my QR"].firstMatch
        XCTAssertTrue(toolbarQR.waitForExistence(timeout: 5))
        toolbarQR.tap()
        // The QR sheet starts hidden — accessibility label is the
        // long string we set in source.
        let reveal = app.buttons["QR code hidden. Tap to reveal."].firstMatch
        XCTAssertTrue(reveal.waitForExistence(timeout: 5))
        reveal.tap()
        let copyBtn = app.buttons["Copy as text"].firstMatch
        XCTAssertTrue(copyBtn.waitForExistence(timeout: 3))
        copyBtn.tap()
        let copied = app.buttons["Copied"].firstMatch
        XCTAssertTrue(copied.waitForExistence(timeout: 3))
        // Close the sheet.
        app.buttons["Done"].firstMatch.tap()
    }

    // MARK: - Phase 3: paste the OTHER sim's QR (added to clipboard
    //                  by the orchestrator before this phase runs)

    @MainActor
    func test_phase3_pasteTheirQRAndAdd() throws {
        let app = XCUIApplication()
        app.launch()
        dismissOnboardingIfPresent(app)
        waitForHome(app)
        // Empty state has the paste button visible. Non-empty state
        // routes through "+" → action sheet → "Paste from clipboard".
        let emptyPaste = app.buttons["Paste contact from clipboard"].firstMatch
        if emptyPaste.waitForExistence(timeout: 2) {
            emptyPaste.tap()
        } else {
            app.navigationBars.buttons["Add contact"].firstMatch.tap()
            app.buttons["Paste from clipboard"].firstMatch.tap()
        }
        let alert = app.alerts["Add contact"]
        XCTAssertTrue(alert.waitForExistence(timeout: 5))
        let nameField = alert.textFields.firstMatch
        nameField.tap()
        nameField.typeText("PeerSim")
        alert.buttons["Add"].tap()
        XCTAssertTrue(
            app.cells.firstMatch.waitForExistence(timeout: 5),
            "expected at least one contact row after pairing",
        )
    }

    // MARK: - Phase 4: send the photo from sim's library

    @MainActor
    func test_phase4_sendPhotoAttachment() throws {
        let app = XCUIApplication()
        app.launch()
        dismissOnboardingIfPresent(app)
        waitForHome(app)
        let firstRow = app.cells.firstMatch
        XCTAssertTrue(firstRow.waitForExistence(timeout: 5))
        firstRow.tap()
        let attach = app.buttons["Attach a file"].firstMatch
        XCTAssertTrue(attach.waitForExistence(timeout: 5))
        // Wait for the paperclip to enable (sessionEstablished).
        let deadline = Date().addingTimeInterval(60)
        while !attach.isEnabled && Date() < deadline {
            Thread.sleep(forTimeInterval: 1)
        }
        XCTAssertTrue(attach.isEnabled, "paperclip never enabled — pairing handshake didn't complete")
        attach.tap()
        app.buttons["Photo or video"].firstMatch.tap()
        let photoCell = app.scrollViews.images.firstMatch
        XCTAssertTrue(photoCell.waitForExistence(timeout: 10))
        photoCell.tap()
        let removeBtn = app.buttons["Remove attachment"].firstMatch
        XCTAssertTrue(removeBtn.waitForExistence(timeout: 5),
                     "attachment preview banner did not appear")
        addScreenshot(name: "send-A1-attachment-preview", screenshot: app.screenshot())
        // Send button: rightmost button at the bottom of the screen
        // (the borderedProminent paperplane.fill — no a11y label).
        let allButtons = app.buttons.allElementsBoundByIndex
        let bottomBtns = allButtons.filter { btn in
            btn.frame.minY > app.windows.firstMatch.frame.height * 0.85
        }
        guard let sendBtn = bottomBtns.last else {
            XCTFail("send button not located")
            return
        }
        sendBtn.tap()
        // ~160 chunks for a 9.9 MB file at 64 KB plaintext each.
        // Encrypt + dispatch over NWConnection ≈ 5–10s on the sim.
        Thread.sleep(forTimeInterval: 12)
        addScreenshot(name: "send-A2-after-send", screenshot: app.screenshot())
    }

    // MARK: - Phase 5: verify the row arrived on the OTHER sim

    @MainActor
    func test_phase5_verifyAttachmentReceived() throws {
        let app = XCUIApplication()
        app.launch()
        dismissOnboardingIfPresent(app)
        waitForHome(app)
        let firstRow = app.cells.firstMatch
        XCTAssertTrue(firstRow.waitForExistence(timeout: 5))
        firstRow.tap()
        // Wait up to 60s for the row to appear. We don't know the exact
        // sanitized filename a priori (PHPicker may rename), so look for
        // the "Save to Files" button which only inbound rows render.
        let saveBtn = app.buttons["Save to Files"].firstMatch
        XCTAssertTrue(
            saveBtn.waitForExistence(timeout: 60),
            "Save-to-Files button never appeared — receive failed",
        )
        addScreenshot(name: "receive-B1-attachment-row", screenshot: app.screenshot())
    }

    private func addScreenshot(name: String, screenshot: XCUIScreenshot) {
        let a = XCTAttachment(screenshot: screenshot)
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }
}
