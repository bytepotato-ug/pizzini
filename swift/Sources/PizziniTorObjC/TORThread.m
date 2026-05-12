//
//  TORThread.m
//  Tor
//
//  Created by Conrad Kramer on 7/19/15.
//

#import <feature/api/tor_api.h>

#import "TORThread.h"
#import "TORLogging.h"
#import "TORConfiguration.h"

NS_ASSUME_NONNULL_BEGIN

// Pizzini change: hold the per-process singleton STRONGLY rather than
// weakly. The upstream iCepa code uses a `__weak` pointer plus an
// NSAssert in the initialiser, both of which are problematic in
// production:
//
//   * NSAssert is compiled out under NS_BLOCK_ASSERTIONS=1 (the App
//     Store release default), so a second `[TORThread initWith…]`
//     call in a release build would silently allocate and start a
//     second tor instance, invoking `tor_run_main()` twice in the
//     same process — undefined behaviour in C-tor.
//
//   * `__weak` lets ARC reset `_thread` to nil if every strong
//     reference is dropped (a future refactor in TorController, a
//     stopInternal() that forgets the comment, etc.), at which
//     point the guard above is vacuously satisfied and a second
//     TORThread can be created — same crash, same UB.
//
// Strong ownership pins the singleton for the process lifetime
// (matching what `tor_run_main` already assumes about the daemon
// it runs), and the replacement guard below uses `if + abort()` so
// the protection survives Release builds.
static TORThread *_thread = nil;

@interface TORThread ()

@property (nonatomic, readonly, copy, nullable) NSArray<NSString *> *arguments;

@end

@implementation TORThread

+ (nullable TORThread *)activeThread {
    return _thread;
}

- (instancetype)init {
    return [self initWithArguments:nil];
}

- (instancetype)initWithConfiguration:(nullable TORConfiguration *)configuration {
    return [self initWithArguments:[configuration compile]];
}

- (instancetype)initWithArguments:(nullable NSArray<NSString *> *)arguments {
    if (_thread != nil) {
        // Hard fail in BOTH debug and release. `tor_run_main` is
        // single-shot per process; reaching this point indicates a
        // logic bug in the caller (TorController.runBootstrap is
        // expected to short-circuit on `[TORThread activeThread]`
        // before constructing a second instance). Crash loudly so
        // we don't silently produce two tor processes inside one
        // app.
        NSLog(@"[pizzini-tor] FATAL: TORThread initialised twice in one process; aborting");
        abort();
    }
    self = [super init];
    if (!self)
        return nil;

    _thread = self;
    _arguments = [arguments copy];

    self.name = @"Tor";

    return self;
}

- (void)main {
    NSArray *arguments = self.arguments;
    int argc = (int)(arguments.count + 1);
    char *argv[argc];
    argv[0] = "tor";
    for (NSUInteger idx = 0; idx < arguments.count; idx++)
        argv[idx + 1] = (char *)[arguments[idx] UTF8String];
    argv[argc] = NULL;

//#if DEBUG
//    event_enable_debug_mode();
//#endif

    tor_main_configuration_t *cfg = tor_main_configuration_new();
    tor_main_configuration_set_command_line(cfg, argc, argv);
    tor_run_main(cfg);
    tor_main_configuration_free(cfg);
}

@end

NS_ASSUME_NONNULL_END
