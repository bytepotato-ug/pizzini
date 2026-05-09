import XCTest

/// UI smoke test for the Phase 3 attach flow. Runs against an installed
/// build that already has at least one paired contact (the maintainer's
/// stable sim has "Real IPhone Contact" pre-populated). Skips if the
/// contacts list is empty on launch — UITests don't programmatically
/// pair, so a clean install can't be exercised.
///
/// Captures three screenshots as test attachments:
///  - the contacts list (sanity)
///  - the chat composer with the paperclip visible
///  - the action sheet ("Photo or video" / "File") after tapping the
///    paperclip.
final class AttachFlowUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testAttachComposerPath() throws {
        let app = XCUIApplication()
        app.launch()

        attach(name: "01-contacts-list", screenshot: app.screenshot())

        // Open the first contact row. The contacts list uses
        // NavigationLink — its tappable area is identified by the
        // contact's display name appearing as a static text.
        let firstRow = app.cells.firstMatch
        guard firstRow.waitForExistence(timeout: 5) else {
            throw XCTSkip("No contacts in the booted sim — re-pair first to exercise this flow.")
        }
        firstRow.tap()

        let attachButton = app.buttons["Attach a file"]
        XCTAssertTrue(
            attachButton.waitForExistence(timeout: 5),
            "Expected the paperclip button (accessibilityLabel='Attach a file') to appear in the composer."
        )
        attach(name: "02-composer-with-paperclip", screenshot: app.screenshot())

        attachButton.tap()
        let photoButton = app.buttons["Photo or video"]
        XCTAssertTrue(
            photoButton.waitForExistence(timeout: 3),
            "Expected the action sheet to surface 'Photo or video'."
        )
        XCTAssertTrue(
            app.buttons["File"].exists,
            "Expected the action sheet to surface 'File'."
        )
        attach(name: "03-attach-action-sheet", screenshot: app.screenshot())
    }

    private func attach(name: String, screenshot: XCUIScreenshot) {
        let a = XCTAttachment(screenshot: screenshot)
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }
}
