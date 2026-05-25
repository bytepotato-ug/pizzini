import Testing
@testable import pizzini

/// F-ATT-01: `.off` must guarantee that no Pizzini-initiated path renders
/// received attachment bytes — including the Save-to-Files
/// `presentPreview` QuickLook fallback, which is gated on
/// `AttachmentPreviewMode.allowsInAppRender`.
@Suite("AttachmentPreviewMode in-app render gate")
struct AttachmentPreviewRenderGateTests {
    @Test("`.off` never allows an in-app render")
    func offForbidsRender() {
        #expect(AttachmentPreviewMode.off.allowsInAppRender == false)
    }

    @Test("opt-in modes allow an in-app render")
    func optInModesAllowRender() {
        #expect(AttachmentPreviewMode.quickLook.allowsInAppRender == true)
        #expect(AttachmentPreviewMode.inlineThumbnail.allowsInAppRender == true)
    }

    @Test("exactly the non-off modes allow rendering")
    func gateMatchesNonOff() {
        for mode in AttachmentPreviewMode.allCases {
            #expect(mode.allowsInAppRender == (mode != .off))
        }
    }
}
