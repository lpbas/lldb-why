#ifndef LEGACY_API_H
#define LEGACY_API_H

#include <stdint.h>

/// A record header in a legacy C library. `count` is at offset 0x28.
struct legacy_header {
    int64_t magic, version, flags, created, modified;
    int64_t count;
};

/// Declared non-null, but returns NULL for unknown names: Swift trusts the
/// annotation and imports the result as a non-optional pointer.
struct legacy_header * _Nonnull legacy_find_header(const char * _Nonnull name);

/// Calls `block` later on a global (background) queue. The block parameter is
/// not marked Sendable, so a closure written in a @MainActor context stays
/// @MainActor-isolated, and Swift checks that at runtime.
void legacy_run_on_background(void (^ _Nonnull block)(void));

#endif
