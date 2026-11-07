---
name: Wrong or missing verdict
about: why misread a crash, or didn't recognize it
labels: verdict
---

<!--
Before you paste anything: crash output can contain your app's class names,
file paths and messages, sometimes user data. Attach a dump made with
`--anonymize`, and read it before posting. Don't paste raw `why` or `bt`
output from a codebase you can't share.
-->

**What happened**
<!-- The kind of crash, and what you expected why to say. -->

**why's output**
<!-- `why` output, with any names you can't share replaced. -->

**Context dump**
<!--
In lldb, at the crash:

    why dump-context --expect --anonymize -o case.json

Attach case.json. If why refuses to write it ("names survived --anonymize"),
please report that instead, without the dump.
-->

**Environment**
- Xcode version:
- Device or simulator, OS version:
- Debug or Release build:
