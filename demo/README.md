# why-demo

A macOS command-line app with one crash per `why` rule, used by the
integration tests and handy for trying `why` out.

```bash
swift build --package-path demo
demo/.build/debug/why-demo            # lists the scenarios
lldb -o "command script import why" -o run -k why -- demo/.build/debug/why-demo big-enum
```

Use `-k` (not `-o`) for commands that should run after the crash: in
`--batch` mode lldb skips the remaining `-o` commands once the process crashes.

Scenarios are written the way the bug usually appears in real code. A few
details:

* `recursion` and `big-enum` run on threads with iOS-sized stacks (512 KB and
  1 MB). `recursion-main` uses the macOS main thread (8 MB, ~174k frames).
* `nil-pointer` and `actor-isolation` go through the small C target
  `LegacyAPI`: a function annotated `_Nonnull` that returns NULL, and a block
  callback that isn't marked Sendable. Pure Swift doesn't produce either crash.
* `use-after-free` over-releases through `Unmanaged`. On current macOS, freed
  small blocks are zeroed, so the crash happens inside `_swift_release_dealloc`.
* The app is built in Swift 6 language mode, which inserts the runtime
  actor-isolation check that `actor-isolation` trips.
