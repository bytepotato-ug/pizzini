import Foundation
import Testing
@testable import pizzini

/// PZ-L7: the attachment reassembler bounds per-peer in-flight count
/// (`perPeerPendingCap`) but, before this fix, had no GLOBAL ceiling —
/// so N distinct paired peers each just under their per-peer cap could
/// collectively pin arbitrary disk. The global byte budget is enforced
/// at chunk-write time via `wouldExceedDiskBudget`, a pure + nonisolated
/// predicate that runs on the simulator without entitlements.
@Suite("PZ-L7 global attachment disk budget")
struct AttachmentDiskBudgetTests {
    private let budget: UInt64 = 256 * 1024 * 1024

    @Test("admits writes up to and including the budget")
    func admitsUpToBudget() {
        #expect(!AttachmentReassembler.wouldExceedDiskBudget(
            inFlight: 0, incoming: 100, budget: budget))
        // A write that fills the budget EXACTLY is allowed.
        #expect(!AttachmentReassembler.wouldExceedDiskBudget(
            inFlight: budget - 64, incoming: 64, budget: budget))
        #expect(!AttachmentReassembler.wouldExceedDiskBudget(
            inFlight: 0, incoming: budget, budget: budget))
    }

    @Test("rejects the write that would exceed the budget")
    func rejectsOverBudget() {
        // One byte past the budget.
        #expect(AttachmentReassembler.wouldExceedDiskBudget(
            inFlight: budget - 64, incoming: 65, budget: budget))
        // Already exactly full → any further byte rejected.
        #expect(AttachmentReassembler.wouldExceedDiskBudget(
            inFlight: budget, incoming: 1, budget: budget))
        // Already over (e.g. budget was lowered) → rejected.
        #expect(AttachmentReassembler.wouldExceedDiskBudget(
            inFlight: budget + 1, incoming: 0, budget: budget))
    }

    @Test("is overflow-safe at the UInt64 ceiling")
    func overflowSafe() {
        // `inFlight + incoming` would wrap UInt64, but the predicate
        // never forms that sum — it compares against `budget - inFlight`.
        #expect(AttachmentReassembler.wouldExceedDiskBudget(
            inFlight: .max - 10, incoming: 100, budget: .max))
        #expect(!AttachmentReassembler.wouldExceedDiskBudget(
            inFlight: .max - 10, incoming: 5, budget: .max))
    }

    @Test("configured budget is 256 MiB")
    func budgetValue() {
        #expect(AttachmentReassembler.globalInFlightByteBudget == 256 * 1024 * 1024)
    }
}
