# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
