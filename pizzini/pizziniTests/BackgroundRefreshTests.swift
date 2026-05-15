//  BackgroundRefreshTests.swift
//  pizziniTests
//
//  Regression pin for P2-8 — APNs silent-push graceful
//  degradation. The pure helpers in `BackgroundRefresh` are the
//  testable decision surface; the BGTaskScheduler side effects
//  (register/submit/handle) are wired in AppDelegate + ContentView
//  and only exercise on a real device with the Info.plist
//  entitlements set.
//
//  What this pins:
//   - The reverse-DNS identifier stays stable (any change here
//     must match the pbxproj's INFOPLIST_KEY_BGTaskScheduler
//     PermittedIdentifiers; the iOS scheduler refuses to register
//     a task whose ID isn't whitelisted).
//   - The cadence floor (1 h) is the hint we send iOS — lower
//     values don't make iOS fire sooner, they only look greedier
//     in the scheduling budget.
//   - The handler self-budget stays inside iOS's own ~30s cap.
//   - The submit gate refuses to schedule from `.active` (we're
//     foregrounded, the on-foreground reconnect handles drain) and
//     refuses to stack a second submit while a handler is in
//     flight (the OS dedups, but we want the policy explicit and
//     testable).

import BackgroundTasks
import Foundation
import Testing
import UIKit
@testable import pizzini

@Suite("BackgroundRefresh decision invariants (P2-8)")
struct BackgroundRefreshTests {

    @Test func identifierMatchesPbxprojWhitelist() {
        // The string here must equal the value of
        // INFOPLIST_KEY_BGTaskSchedulerPermittedIdentifiers in
        // pizzini.xcodeproj/project.pbxproj for both Debug AND
        // Release configurations. Changing the value below
        // without also editing the pbxproj will leave a build
        // where BGTaskScheduler.shared.register returns false at
        // runtime and the secondary wake-up path silently dies.
        #expect(BackgroundRefresh.identifier == "app.pizzini.bgrefresh")
    }

    @Test func cadenceFloorIsHourlyOrSlower() {
        // 1 h is the canonical messenger-style cadence. Anything
        // shorter is wasted budget — iOS will fire when iOS wants
        // to, not when we ask. Anything longer is fine policy-wise
        // but defeats the "secondary wake every reasonable amount
        // of time" intent.
        #expect(BackgroundRefresh.earliestRefreshInterval >= 60 * 60)
    }

    @Test func handlerBudgetStaysInsideIosHardCap() {
        // iOS hard-caps `BGAppRefreshTask` handlers at ~30s before
        // the expiration handler fires. We self-cap below that so
        // we complete gracefully rather than being forced — a
        // forced expiration lowers our scheduling priority in
        // iOS's eyes.
        #expect(BackgroundRefresh.handlerBudgetSeconds < 30)
    }

    @Test func nextEarliestBeginDateIsExactlyFloorAhead() {
        let submitted = Date(timeIntervalSince1970: 1_000_000_000)
        let next = BackgroundRefresh.nextEarliestBeginDate(
            submittedAt: submitted,
            cadenceFloor: 60 * 60,
        )
        #expect(next.timeIntervalSince(submitted) == 60 * 60)
    }

    @Test func activeAppDoesNotScheduleRefresh() {
        // Foregrounded → on-foreground reconnect already drains the
        // backlog; submitting a BG refresh is wasted budget.
        #expect(
            BackgroundRefresh.shouldSubmit(
                appState: .active,
                handlerInFlight: false,
            ) == false
        )
    }

    @Test func backgroundedAppSchedules() {
        #expect(
            BackgroundRefresh.shouldSubmit(
                appState: .background,
                handlerInFlight: false,
            ) == true
        )
    }

    @Test func inactiveAppSchedules() {
        // `.inactive` is the brief transition state (incoming
        // call, multitasking gesture). Best to schedule here too
        // — by the time `.background` lands we may have missed
        // the window.
        #expect(
            BackgroundRefresh.shouldSubmit(
                appState: .inactive,
                handlerInFlight: false,
            ) == true
        )
    }

    @Test func handlerInFlightDefersResubmit() {
        // A second submit while a handler is running gets queued
        // behind it by iOS and may be dropped as spam. The handler
        // itself calls `submit()` again on completion — that's the
        // right place to chain the next fire.
        #expect(
            BackgroundRefresh.shouldSubmit(
                appState: .background,
                handlerInFlight: true,
            ) == false
        )
    }
}
