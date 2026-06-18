// __clear_cache shim for iOS device builds.
//
// Tor's PoW module (enabled via `--enable-gpl --enable-module-pow` in
// scripts/build-tor-xcframework.sh) pulls in Equi-X, whose hashx hash
// function JIT-compiles to native ARM64 (libhashx, compiler_a64.o) and
// calls `__builtin___clear_cache` to flush the instruction cache after
// emitting code. That lowers to the `___clear_cache` compiler-rt builtin.
//
// Apple does NOT ship `__clear_cache` in the iOS builtins (libclang_rt.ios.a)
// — iOS forbids the runtime code generation the builtin exists for — so a
// device link fails with "Undefined symbol: ___clear_cache" referenced
// from `_hashx_compile_a64`. The simulator toolchain DOES provide it,
// which is why only device builds break.
//
// Provide the Apple-correct equivalent via `sys_icache_invalidate`. On a
// normal (non-JIT-entitled) iOS app, hashx cannot map executable memory
// and falls back to its interpreter, so this is never actually called —
// it only satisfies the linker. If the JIT ever does run (e.g. an
// entitled/jailbroken device), the icache flush is still correct.
//
// Exported via an `__asm__` label as the exact Mach-O symbol the linker
// wants (`___clear_cache`), so the source function name does not collide
// with the `__clear_cache` compiler builtin.

#include <libkern/OSCacheControl.h>

void pizzini_clear_cache_shim(void *begin, void *end) __asm__("___clear_cache");

void pizzini_clear_cache_shim(void *begin, void *end) {
    sys_icache_invalidate(begin, (char *)end - (char *)begin);
}
