# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Stack overflows in an "outlined init with copy of T" helper now report T's
  real size, measured on a variable of that type in the frames above, and the
  enum case or stored property that makes it big. The next step names the
  case to box. No code runs in the crashed process.
- A note when the large frames come from a Debug (unoptimized) build, read
  from the debug info (`SBFunction.GetIsOptimized`).
- `enum-copy` demo scenario: the stack overflows inside the outlined copy
  helper, like the real crash that motivated `why`.
- A real, anonymized iOS fixture of the crash that motivated `why`, replacing
  the modeled one.
- SECURITY.md, an issue template that asks for anonymized dumps, and
  Dependabot for the pinned GitHub Actions.

### Changed
- When your own frames take most of the stack, the verdict says so:
  "8 of your frames take 828.9 KB of the 1008.0 KB stack (largest: ...)".
- "Biggest consumer: X, 1 calls = ..." now reads "X, 322.8 KB in one call".

### Security
- `why dump-context --anonymize` now renames every symbol, path, module and
  type from your code (including inside SwiftUI generics), drops crash
  messages and exception reasons down to the standard phrases rules match,
  removes app queue and thread names, and refuses to write the file if an
  original name survives. Before, it only replaced the home folder.
- Control characters and bidi overrides in text from the debugged app are
  replaced before printing, so a crash message can't send escape sequences to
  your terminal.
- Variables are always read without running code in the app, whatever
  `target.prefer-dynamic-value` is set to.
- Internal error tracebacks show `~` instead of your home folder.
- CI runs with read-only permissions and actions pinned to commit SHAs.

## [0.1.0]

### Added
- `why` / `diagnose`: one-line verdict with confidence, evidence, the first
  frame in your code, and next steps.
- `why stack`: stack usage report at any stop, including the frame size
  requested from `___chkstk_darwin` (caller's prologue, cross-checked with x9).
- `why auto on|off|status`: stop hook that explains crashes as they happen.
- `why dump-context`: JSON export of the gathered data, usable as a test fixture.
- Rules for stack overflows, nil dereferences, use-after-free and
  over-release, garbage function pointers, Malloc Scribble patterns, corrupted
  pointers, writes to read-only memory, heap corruption and double frees,
  Swift concurrency isolation violations, Swift runtime traps, libdispatch /
  libplatform misuse, sanitizer reports, Objective-C and C++ exceptions,
  `assert()` and `abort()`.
- Demo app with 17 crash scenarios, unit and integration tests, and CI on macOS.
