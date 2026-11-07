# Security

## Reporting a problem

Please report security problems privately through GitHub:
**Security > Report a vulnerability** on this repository
(https://github.com/lpbas/lldb-why/security/advisories/new). Don't open a
public issue. You should get a reply within a week.

Things worth reporting, for example:

* `why dump-context --anonymize` leaves a name, path or message from your app
  in the dump.
* `why` runs code in the debugged process, changes its state, or writes
  anywhere other than the file you passed with `-o`.
* Text from a debugged app can inject terminal escape sequences or lldb
  commands through `why`'s output.

## What why does and doesn't do

* It runs inside your lldb session and only reads: stop information, frames,
  registers, memory region info, the caller's instructions, and the size of
  variables. It doesn't evaluate expressions or run code in the app, and it
  doesn't resume, stop or modify the process.
* It makes no network requests and collects no telemetry.
* It writes a file only for `why dump-context -o <file>`.

## Sharing crash data

`why` output and `why dump-context` files contain what the debugger sees:
your app's symbol names, source paths, queue names, crash messages and
exception reasons, which can include user data. Before sharing a dump, create
it with `--anonymize`, which renames everything that comes from your code and
keeps only Apple framework names, addresses and sizes. Then read it anyway.
