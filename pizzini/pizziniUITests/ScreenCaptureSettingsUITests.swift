import XCTest

/// Drives the top-level Settings sheet and asserts the screen-capture
/// section renders. Previously this section was buried under
/// Settings → App lock; users couldn't find it. Promoted to its own
/// top-level Settings section alongside Connection / Security /
/// Attachments / Help / Advanced.
///
/// We don't try to flip iOS's recording state from a UITest
/// (impossible from inside the sim), but we verify the user-facing
/// toggles exist and the rows are tappable from the Settings root.
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
    func test_screenCaptureSection_rendersAtSettingsRoot() throws {
        let app = XCUIApplication()
        app.launch()
        dismissOnboardingIfPresent(app)

        // Open Settings from the home toolbar.
        let gear = app.navigationBars.buttons["Settings"].firstMatch
        XCTAssertTrue(gear.waitForExistence(timeout: 5))
        gear.tap()

        // Section header is at the Settings root — no need to navigate
        // into App lock anymore.
        let header = app.staticTexts["Screen capture"].firstMatch
        XCTAssertTrue(
            header.waitForExistence(timeout: 5),
            "Screen-capture section should be visible at the Settings root",
        )

        // Both toggles surface their label text. The mask toggle is
        // disabled when the runtime self-test failed (`qrBlockEffective
        // == false`), but the row still renders, so this assertion
        // holds either way.
        let blockToggle = app.switches["Block screenshots of Pizzini"].firstMatch
        XCTAssertTrue(
            blockToggle.waitForExistence(timeout: 3),
            "blockAppScreenshots toggle must render with its label",
        )
        let notifyToggle = app.switches["Tell my contact when I screenshot"].firstMatch
        XCTAssertTrue(
            notifyToggle.waitForExistence(timeout: 3),
            "notifyPeerOnScreenshot toggle must render with its label",
        )
    }
}
