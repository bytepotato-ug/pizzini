// The QA-log clear-on-wipe test (F-DUR-01) that used to live here was
// merged into `QALogTests` (the single `.serialized` QALog suite) as
// `clearRemovesActiveLogForDuress()`.
//
// Why: this was a SEPARATE `@Suite` that touched the same fixed on-disk
// path (`Library/Application Support/qa-debug/`) as `QALogTests`. Swift
// Testing's `.serialized` trait only orders the tests WITHIN one suite —
// two distinct suites still run in parallel — so this suite's `clear()`
// raced `QALogTests`' `resetDir()` / `record()`, producing flaky
// "qa.log couldn't be opened" / "qa-debug couldn't be removed" failures
// in the full bundle (each suite passed in isolation). Folding every
// qa-debug-touching case into one `.serialized` suite makes that path
// single-owner and the cases deterministic.
//
// This file is intentionally left as documentation only; the Xcode test
// target still references it.
