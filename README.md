# why

**Plain-English crash explanations in lldb and Xcode's debug console.**

When an app crashes under the debugger, Xcode shows `EXC_BAD_ACCESS (code=2,
address=0x16fe03ff8)` and a stack full of compiler-generated frames. The
information needed to diagnose it is usually there: the exception code, the
faulting address, which memory region it is in, the stack pointer of every
frame, frame 0's symbol. It just isn't interpreted. `why` interprets it.

## Before and after

What the debugger gives you (real output from the [demo app](demo/README.md)'s
`enum-copy` scenario, shaped on a real SwiftUI crash):

```
* thread #2, stop reason = EXC_BAD_ACCESS (code=2, address=0x16fe03ff8)
  * frame #0: 0x0000000180672c5c libsystem_pthread.dylib`___chkstk_darwin + 60
    frame #2: 0x0000000100007b48 why-demo`makeRow(template=why_demo.ListItem, index=30) at main.swift:103:61
    frame #3: 0x0000000100008028 why-demo`closure #1 in screenBody(count=0, highlighted=why_demo.ListItem, level=30) at main.swift:112:63
    ...
```

`bt` even hides frame #1, the compiler-generated helper that actually ran out
of stack. What `why` adds:

```
(lldb) why
why: Stack overflow: 38 of your frames take 1.01 MB of the 1.03 MB stack (screenBody(_:level:) uses 30.5 KB per call, 31 calls deep)  [confidence: high]

Evidence
  - EXC_BAD_ACCESS code=2 (KERN_PROTECTION_FAILURE: memory is mapped there, but this kind of access is not allowed) at address 0x16fe03ff8
  - Address 0x16fe03ff8 is 8 B below the stack of thread #2, in its guard page
  - Crashed in #0 ___chkstk_darwin (libsystem_pthread.dylib)
  - Stack: 1.01 MB used of 1.03 MB (98.0%) across 41 frames on thread #2
  - Frame 0 is ___chkstk_darwin, the stack probe for big frames: #1 outlined init with copy of ListItem.EndContent? at <compiler-generated> (why-demo) asked for 15.0 KB (15312 bytes, from caller's prologue, matches x9) but only 928 B was left
  - Size: ListItem.EndContent? is 7.5 KB (7697 bytes, measured on `template.end` in frame #2). Almost all of it is case .scoreboard: `.scoreboard.0` is ListItem.Scoreboard, 7.5 KB
  - Biggest consumer: screenBody(_:level:), 31 calls = 944.5 KB (30.5 KB per call)

Where
  - Your code: #2 makeRow(_:index:) at main.swift:103 (why-demo)
  - Via compiler-generated #1 outlined init with copy of ListItem.EndContent? at <compiler-generated> (why-demo)

Stack
  - Largest frames: 52.8 KB enumCopy(), 30.5 KB screenBody(_:level:)
  - Frames: 38 yours (1.01 MB), 0 SwiftUI (0 B), 3 system (608 B)

Notes
  - 'outlined init with copy of ListItem.EndContent?' is a compiler-generated helper that copies a value of type ListItem.EndContent?, and every copy reserves 7.5 KB of stack. An enum is as large as its largest case, so every ListItem.EndContent? is 7.5 KB because of case .scoreboard, even when it holds a small case or nil
  - Large Swift frames come from big value types (structs/enums with many stored properties or large payloads) being copied or kept in locals. Box large payloads (an `indirect` enum case or a final class wrapper) so each copy is one pointer
  - This is a Debug build: without optimization (-Onone) every temporary gets its own stack slot, so frames are often several times bigger than in Release. A Release build may not crash here, but it copies the same values, so make the type smaller rather than rely on the optimizer
  - Default stacks: iOS main thread ~1 MB, secondary threads 512 KB, macOS main thread 8 MB. The simulator may use macOS's limits, so overflows can show up only on device

Next steps
  1. Box the payload of case .scoreboard: write `indirect case scoreboard(...)`, or keep ListItem.Scoreboard in a final class. Then `expression -l swift -- MemoryLayout<ListItem.EndContent?>.size` should drop well below 7697
  2. Run `why stack` for the full stack usage report
```

## Install

Clone the repository, then add one line to `~/.lldbinit`:

```
command script import /path/to/lldb-why/why
```

Xcode reads `~/.lldbinit-Xcode` instead if that file exists, so put the line
there too if you have one. To explain every crash automatically, add a second line:

```
why auto on
```

No dependencies: `why` is pure Python and runs on the Python that ships with
Xcode's lldb (3.9 and later).

## Commands

| Command | What it does |
|---|---|
| `why` (alias `diagnose`) | Explains the current stop of the crashed thread: a one-line verdict with a confidence level, the evidence, the first frame in your code, and next steps. |
| `why stack` | The full stack usage report: region, total used and %, frame 0's headroom, the largest frames, usage by function, and frames in your code vs SwiftUI vs system. Works at any stop, so you can profile deep view hierarchies at a breakpoint. `--top N` lists more frames. |
| `why auto on` / `off` / `status` | Installs a stop hook that runs `why` when the process crashes. It stays quiet on breakpoints, steps and other stops. |
| `why dump-context` | Prints the data `why` gathered as JSON. `--expect` wraps it as a unit-test fixture, `--anonymize` renames everything from your code (see [Privacy](#privacy)), `-o file` writes to a file. |

Options: `-t N` picks a thread, `--json` prints the diagnosis as JSON, and
`--color` / `--no-color` override color. Output is plain text by default,
because Xcode's console doesn't render ANSI colors. In a terminal, `why`
follows lldb's own color setting; `WHY_COLOR=0` or `WHY_COLOR=1` overrides both.

## What it recognizes

Rules are checked in order; the first match wins.

| Crash | How it's recognized | Confidence |
|---|---|---|
| **Stack overflow**: infinite recursion, deep recursion, a deep chain of large frames, or one oversized frame | Frame 0 is `___chkstk_darwin`, the fault is within 128 KB below the thread's stack, or sp is already below it. For chkstk, the requested frame size is read from the caller's prologue and cross-checked with x9. When the frame is a compiler-generated copy helper, the copied value is measured from a variable in the frames above (no code runs in the app), down to the enum case or property that makes it big. | high |
| **Heap corruption / double free** | malloc's own error paths (`___BUG_IN_CLIENT_OF_LIBMALLOC_...`, `malloc_error_break`, a trap inside `libsystem_malloc`) | high |
| **Use-after-free / over-release** | A bad access inside `swift_retain/release`, `_swift_release_dealloc`, `objc_retain/release` or `objc_msgSend` | high |
| **Garbage function pointer or closure** | fault address == pc | high |
| **Malloc Scribble patterns** | `0x5555...` (freed) or `0xAAAA...` (uninitialized) | high |
| **Corrupted pointer / pointer authentication failure** | Bits outside the process's address mask are set | medium |
| **Nil / NULL dereference** | Address inside `__PAGEZERO`, or NULL minus a small offset. Reports the field offset. | high |
| **Write to read-only memory** | code=2 on readable, non-writable memory; names the section (e.g. a string literal in `__TEXT.__cstring`) | high |
| **Bad heap access** | Fault in a malloc region (from debugserver's region type) | medium |
| **Swift concurrency isolation violation** | `_dispatch_assert_queue_fail` / `swift_task_isCurrentExecutor*` / `swift_task_checkIsolated*` near the top | high |
| **Swift runtime traps**: force unwrap, implicitly unwrapped nil, index out of range, overflow, division by zero, invalid range, `unowned` after deinit, exclusivity violations, duplicate keys, numeric conversions, failed `as!`, `fatalError`, `precondition` | lldb's Swift runtime reporting stop (debug builds) or the inlined `Swift runtime failure: ...` frame (optimized builds) | high |
| **API misuse**: `DispatchQueue.sync` onto the current queue, unbalanced `DispatchGroup.leave()`, recursive `os_unfair_lock` | libdispatch / libplatform trap frames | high |
| **Sanitizer reports** (Address / Thread / UB Sanitizer) | Instrumentation stops | high |
| **Uncaught Objective-C exception** | `SBThread.GetCurrentException()`: name, reason, and the throw site from the exception's own backtrace | high |
| **Uncaught C++ exception**, **C `assert()`**, **deliberate `abort()`** | Frames of the abort path | medium |
| Anything else | A short explanation of the exception type and the raw evidence | low |

Each verdict comes with next steps: which Xcode diagnostic to enable (Address
Sanitizer, Zombie Objects, Malloc Scribble, Malloc Stack Logging, Thread
Sanitizer, an Exception Breakpoint) or which lldb command to run next.

## Privacy

`why` only reads from the debugger: it doesn't run code in your app, change
the process, make network requests or collect telemetry. Output is printed to
your console, and the only file it writes is the one you name with
`why dump-context -o`.

That output does contain what the debugger sees: your app's symbol names,
source paths, queue names and crash messages. Before sharing a dump, make it
with `--anonymize`:

* Names from your code become placeholders (`Module1`, `Type3`, `name2`),
  consistently, including your types inside SwiftUI generics.
* Paths to your code become `/redacted/...`, and your home folder becomes `~`.
* Crash messages and exception reasons keep only the standard phrases `why`
  recognizes (`Index out of range`, `unrecognized selector`), and app queue
  and thread names are removed.
* Apple framework names, addresses, sizes and registers are kept, so the dump
  still produces the same diagnosis.

`why` checks the result and refuses to write the file if any original name is
still in it. Read it before sharing anyway. See [SECURITY.md](SECURITY.md) to
report a problem privately.

## How it works

Two layers:

1. **`why/core`**: a pure classifier with no `import lldb`. It takes a plain
   `CrashContext` (stop info, frames with symbols and stack pointers, memory
   regions, registers, any language exception) and returns a `Diagnosis`. That
   keeps it unit-testable from JSON fixtures, and reusable later for `.ips`
   crash reports from devices.
2. **`why/lldb_adapter`**: gathers a `CrashContext` through the SB API, then
   prints the diagnosis.

[docs/FINDINGS.md](docs/FINDINGS.md) records what lldb actually reports in
each situation. Several details are not what you'd guess: for example, the
chkstk frame size is passed in x9 in bytes, and Swift traps in debug builds
don't arrive as `EXC_BREAKPOINT`.

## Adding a rule

Rules are entries in the `RULES` table in [`why/core/rules.py`](why/core/rules.py):

```python
Rule(
    id="write-readonly",
    category="bad_access",                       # which stops it applies to
    when=lambda f: (f.code == 2 and f.ctx.fault_region is not None
                    and f.ctx.fault_region.readable and not f.ctx.fault_region.writable),
    verdict="Wrote to read-only memory: {fault} is constant data",
    confidence="high",
    next_steps=["Copy the data into memory you own before writing", Steps.ASAN],
)
```

Reproduce the crash under lldb and run `why dump-context --expect --anonymize -o tests/unit/fixtures/my_case.json`,
then edit the `expect` block. [CONTRIBUTING.md](CONTRIBUTING.md) has the details.

## iOS

The classifier works the same for iOS devices and simulators. The differences
are in the inputs, and `why` reads each one from the live process instead of
hardcoding it:

* Stack sizes: iOS main thread ~1 MB, secondary threads 512 KB; the macOS main
  thread has 8 MB. The Simulator runs as a macOS process and may get macOS's
  limits, so an overflow can show up only on device.
* The address mask (devices use a smaller address space).
* System code on devices is arm64e, so pointer authentication failures can happen there.
* On Intel Macs and x86_64 simulators, the chkstk size is read from `rax`.

CI runs on macOS only; the iOS points above are documented, not tested.

## Development

```bash
python3 -m unittest discover -s tests/unit            # no debugger needed
python3 -m unittest discover -s tests/integration -v  # builds demo/, runs lldb
python3 tests/integration/capture_fixtures.py         # refresh fixtures from the demo
```

## License

MIT, see [LICENSE](LICENSE).
