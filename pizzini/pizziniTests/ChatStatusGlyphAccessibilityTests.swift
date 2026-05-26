import Foundation
import Testing
@testable import pizzini

/// PZ-H10: every chat send-status glyph must carry a VoiceOver label.
/// The glyphs previously used only `.help()`, which VoiceOver ignores,
/// so a VoiceOver user heard a bare unlabeled image and could not tell
/// pending from sent from delivered from read from failed.
@Suite("Chat status glyph accessibility (PZ-H10)")
struct ChatStatusGlyphAccessibilityTests {

    @Test
    func everyKindHasANonEmptyLabel() {
        for kind in ChatStatusGlyph.Kind.allCases {
            #expect(
                !kind.accessibilityLabel.trimmingCharacters(in: .whitespaces).isEmpty,
                "status glyph kind \(kind) has an empty accessibility label"
            )
        }
    }

    @Test
    func labelsAreDistinct() {
        let labels = ChatStatusGlyph.Kind.allCases.map(\.accessibilityLabel)
        #expect(
            Set(labels).count == labels.count,
            "status glyph accessibility labels must be distinct so each status is distinguishable"
        )
    }

    /// Guards against a future glyph being added to the enum without a
    /// label — `allCases` would grow but the switch in `accessibilityLabel`
    /// is exhaustive, so this also pins the count we expect today.
    @Test
    func coversAllFiveStatuses() {
        #expect(ChatStatusGlyph.Kind.allCases.count == 5)
    }
}
