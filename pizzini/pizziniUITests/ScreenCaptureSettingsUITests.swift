import XCTest

/// Drives Settings → App lock and asserts the new screen-capture
/// section's accessibility labels render. We don't try to flip iOS's
/// recording state from a UITest (impossible from inside the sim), but
/// we verify the user-facing toggles exist and the rows are tappable.
final class ScreenCaptureSettingsUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    private func dismissOnboardingIfPresent(_ app: XCUIApplication) {
        for _ in 0..<2 {
            let cont = app.buttons["Continue"].firstMatch
            if cont.waitForExistence(timeout: 2) {
                cont.tap()
            } else {
                break
            }
        }
        let skip = app.buttons["Skip — I'll add it later"].firstMatch
        if skip.waitForExistence(timeout: 2) {
            skip.tap()
        }
    }

    @MainActor
    func test_screenCaptureSection_rendersToggles() throws {
        let app = XCUIApplication()
        app.launch()
        dismissOnboardingIfPresent(app)

        // Open Settings → App lock from the home toolbar.
        let gear = app.navigationBars.buttons["Settings"].firstMatch
        XCTAssertTrue(gear.waitForExistence(timeout: 5))
        gear.tap()

        let appLockRow = app.buttons["App lock"].firstMatch
        XCTAssertTrue(appLockRow.waitForExistence(timeout: 3))
        appLockRow.tap()

        // The section header is rendered as static text in the form.
        let header = app.staticTexts["Screen capture"].firstMatch
        XCTAssertTrue(
            header.waitForExistence(timeout: 5),
            "Screen-capture section should be visible under App lock",
        )

        // Both toggles surface their label text — the section above can
        // verify their accessibility labels rendered without us needing
        // to actually flip them. (Toggling persists state through the
        // Keychain and leaks across UITest runs; the brief asks for
        // "rows render the expected accessibility labels", not
        // round-tripping the state.)
        let notifyToggle = app.switches["Tell my contact when I screenshot"].firstMatch
        XCTAssertTrue(
            notifyToggle.waitForExistence(timeout: 3),
            "notifyPeerOnScreenshot toggle must render with its label",
        )
        let blockQRToggle = app.switches["Block screenshots of my QR"].firstMatch
        XCTAssertTrue(
            blockQRToggle.waitForExistence(timeout: 3),
            "blockQRScreenshots toggle must render with its label",
        )
    }
}
