# What lldb actually reports: verified behavior

The classifier is built on these observations, made with Xcode's lldb
(lldb-2103.0.34, Python 3.9.6) on arm64 macOS 26.6, against a probe app with one
crash per scenario. Re-check them when a new Xcode or OS ships. Items marked
*unverified* come from documentation or reasoning, not from a run.

## Running lldb in batch mode

* `lldb --batch -o run -o cmd`: when `run` ends in a crash, the remaining `-o`
  commands are **skipped**. Commands meant to run after a crash go in `-k`:
  `lldb --batch -o run -k why -k quit -- ./demo scenario`.

## Stop information

* `SBThread.GetStopReasonDataAtIndex` gives `[exc_type, code, subcode]` for Mach
  exceptions: `EXC_BAD_ACCESS (code=2, address=0x16f603ff8)` is `[1, 2, 0x16f603ff8]`,
  and `EXC_BREAKPOINT` is `[6, 1, pc]`. The description string never needs parsing.
* Signals (SIGABRT) are `eStopReasonSignal` with data `[6]`.
* **Swift runtime failures in debug builds don't stop as EXC_BREAKPOINT.** lldb's
  `SwiftRuntimeReporting` plugin stops *before* the trap with
  `eStopReasonInstrumentation`. `GetStopReasonExtendedInfoAsJSON` contains
  `"description": "Fatal error: Index out of range"`, `"is_fatal": true` and
  `"instrumentation_class": "SwiftRuntimeReporting"`. Frame 0 is
  `_swift_runtime_on_report`. This also applies to `fatalError()` in `-O` builds.
* In `-O` builds (and for arithmetic overflow even at `-Onone`) checks are inlined:
  `EXC_BREAKPOINT` with an inlined frame 0 whose name is
  `Swift runtime failure: <message>`.

## Memory regions

* `SBMemoryRegionInfo.GetName()` returned `None` for every region: stack, heap,
  images, the shared cache and `__PAGEZERO`.
* debugserver does label regions, but only in the raw packet:
  `process plugin packet send qMemoryRegionInfo:<addr>` returns
  `...;type:stack;` for stacks and `...;type:heap,malloc-small;` for malloc memory.
  Image regions have no type; `SBTarget.ResolveLoadAddress(addr).GetSection()`
  gives the section (`__TEXT.__cstring`) and its module.
* The guard page below a stack has no permissions and no type: it is
  indistinguishable from unmapped memory. A secondary thread has its own 16 KB
  guard region; below the main thread it merges into a ~57 MB unmapped gap.
* `__PAGEZERO` shows as one unmapped region `[0x0-0x100000000)`.
* lldb strips non-address bits before looking up a region (asking about
  `0x4141414141414148` returns a region starting at `0x414141414148`), so
  non-canonical addresses must be checked against the address mask, not the
  region. `SBProcess.GetAddressMask(eAddressMaskTypeData)` returned
  `0xffff800000000000` (47-bit addresses).

## Stacks

* In plain recursion, **frame 0's sp is already inside the guard page**, so the
  region containing frame 0's sp is the unmapped gap, not the stack. The adapter
  takes the region containing the outermost frame's sp instead.
* Region sizes: macOS main thread 8176 KB (8 MB minus the 16 KB guard). A
  `Thread` with `stackSize = 1 MB` got a 1056 KB region.
* Walking 174,001 frames (8 MB of 48-byte frames) took ~2.6 s for
  `GetNumFrames()` plus ~1 s to read sps and names.

## `___chkstk_darwin` (arm64)

Disassembly of `libsystem_pthread.dylib`:

```
stp    x10, x11, [sp, #-0x10]
mrs    x10, TPIDRRO_EL0
ldur   x11, [x10, #-0x30]        ; stack bounds from the thread's TSD
...
subs   x10, x10, x9              ; sp - x9: x9 is the size in BYTES
b.lo   <+60>
cmp    x10, x11
b.lo   <+60>
...
<+60>: ldur x11, [x11, #-0x8]    ; deliberately touch stack_limit - 8 -> fault
<+64>: page-probing loop that decrements x9 by 0x1000 per page
```

The caller:

```
mov    w9, #0x3bd0               ; 15312 bytes
adrp   x16, ... ; ldr x16, [...] ; blr x16   -> ___chkstk_darwin
sub    sp, sp, #0x3, lsl #12
sub    sp, sp, #0xbd0             ; = 15312
```

So:

* The size is in **x9, in bytes** (not x15, and not in 16-byte units; x15 is the
  Windows arm64 convention).
* When the frame doesn't fit, the fault address is always `stack_limit - 8`,
  whatever the frame size. `frame 0 sp - fault` is only a lower bound.
* x9 survives on the fast path, but the probing loop decrements it, so the
  caller's prologue (`mov w9, #imm`) is the authoritative source and x9 the
  cross-check.
* x86_64 passes the size in `rax` (*unverified*, from the ABI).

## Sizing Swift values without running code

Used to report how big the type copied by an "outlined init with copy of T"
helper is (Xcode 26 lldb, Swift 6, debug build):

* `SBTarget.FindFirstType` and `SBModule.FindFirstType` return nothing for
  Swift types, whatever the spelling (`App.ListItem.EndContent`, `Swift.Optional<...>`,
  `ListItem.EndContent?`, the mangled `$s...D` name). `SBModule.GetTypes()` does
  list them, but `SBType.GetByteSize()` is 0 for every Swift type, static or
  dynamic.
* `SBValue.GetByteSize()` on a variable of that type returns the real size
  (7697 bytes for the demo's `ListItem.EndContent?`), takes milliseconds, and
  runs no code in the process. So `why` looks for an argument or local of type
  T (or a stored property of one) in the frames above the helper.
* The helper's `GetFunctionName()` is the qualified type
  (`outlined init with copy of Swift.Optional<why_demo.ListItem.EndContent>`),
  which matches the variable's `GetTypeName()` exactly. The display name uses
  the short spelling (`ListItem.EndContent?`).
* A Swift enum's type class is `eTypeClassUnion`, and its value has one child:
  the case it currently holds, named after the case, with the payload as its
  type (a tuple for several associated values, elements named `0`, `title`,
  ...). An `Optional` of an enum is flattened: its child is the inner case.
* That child is the only case lldb shows. When the value holds a small case or
  nil (the copy still reserves the biggest case's size), the SB API has no way
  to list the others: the enum's `SBType` has no fields, no enum members and
  size 0, and `type lookup` finds nothing. The cases are in the binary's
  reflection metadata, `__TEXT.__swift5_fieldmd`: one record per case with its
  name and the payload's mangled type name, whose symbolic references point at
  the payload types' context descriptors. `why` reads those from the file
  (verified on Xcode 26's lldb, `enum-copy-small` and `enum-copy-nil`).
* A payload type's size: `SBModule.FindTypes("Scoreboard")` finds it (the
  qualified name doesn't), and `value.Cast(thatType).GetByteSize()` returns
  its real size (7680), reading metadata only.
* `SBTarget.FindTypes` is not safe here: it also asks the Objective-C runtime,
  which runs lldb's helper code in the process ("warning: could not execute
  support code to read Objective-C class data"). Search per module instead.
* `SBFunction.GetIsOptimized()` is False for `-Onone` code. The outlined
  helpers have no `SBFunction` (symbol only).
* `bt` hides the compiler-generated helper frame (it prints frames #0, #2, #3,
  ...), but `SBThread.GetFrameAtIndex(1)` returns it.

## Exceptions

* For an uncaught NSException the stop is `SIGABRT` with frames
  `__pthread_kill / abort / ... / _objc_terminate / std::__terminate`.
  `SBThread.GetCurrentException()` is valid there. Its child `name` has the
  name; its summary has the reason. `GetCurrentExceptionBacktrace()` returns the
  backtrace from where it was thrown (`__exceptionPreprocess, objc_exception_throw,
  -[NSException raise], main`).

## Swift concurrency

* A `@MainActor` closure passed to a C function whose block parameter isn't
  Sendable, then called on a global queue, traps with `EXC_BREAKPOINT` in
  `_dispatch_assert_queue_fail`. The Swift frames are at depth 3-4
  (`_swift_task_checkIsolatedSwift`, `swift_task_isCurrentExecutorWithFlagsImpl`),
  and the user's closure is at frame 5.
* A pure-Swift `nonisolated(unsafe) var` holding a `@MainActor` closure, called
  from another thread, does **not** trap.

## Malloc

* With this OS's allocator, `MallocScribble=1` fills new allocations with 0xAA,
  but freed **small** blocks (64 B, 1 KB) are zeroed rather than filled with
  0x55. Large blocks (40 KB) do get 0x55. A use-after-free of a small object
  therefore often looks like a near-NULL dereference.
* An Unmanaged over-release crashed at `0xfffffffffffffff4` (NULL - 12) inside
  `_swift_release_dealloc`, so symbol rules must win over address rules.

## Stop hooks

* `target stop-hook add -P module.Class` run before any target exists (as from
  `~/.lldbinit`) is copied into targets created later, which is how Xcode creates them.
* The hook fires on every stop (SIGSTOP, breakpoints), so it must filter.

## iOS differences (*unverified*)

* Default stacks: main thread ~1 MB, secondary threads 512 KB. The analyzer uses
  the real region size, so nothing is hardcoded.
* Devices use a smaller address space; the mask is read from the process.
* System code on devices is arm64e, so pointer authentication failures are possible
  there; lldb may append "(possible pointer authentication failure)" to the stop
  description.
* The Simulator runs as a macOS process and may get macOS's 8 MB main stack, so
  an overflow can reproduce on device but not in the Simulator.
