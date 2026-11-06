"""Runs every demo scenario under lldb and checks why's verdict.

Needs macOS with Xcode (or the Command Line Tools) and permission to debug
(`DevToolsSecurity -enable`). Builds demo/ with `swift build` unless WHY_DEMO
points at a built why-demo binary. Set LLDB to use a specific lldb.

    python3 -m unittest discover -s tests/integration -v

Note: commands after a crashing `run` must be passed with -k, not -o:
lldb --batch skips the remaining -o commands once the process crashes.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from why.core import CrashContext, diagnose  # noqa: E402

PACKAGE = os.path.join(ROOT, "why")
DEMO_DIR = os.path.join(ROOT, "demo")
LLDB = os.environ.get("LLDB") or shutil.which("lldb")
TIMEOUT = 180

# scenario: (rule_id, confidence, text the verdict must contain)
EXPECTED = {
    "nil-pointer": ("nil-deref", "high", "offset 0x28 of a nil pointer"),
    "recursion": ("stack-overflow", "high", "infinite recursion in countDown(_:)"),
    "recursion-main": ("stack-overflow", "high", "infinite recursion in countDown(_:)"),
    "big-enum": ("stack-overflow", "high", "deep chain of large frames"),
    "use-after-free": ("refcount-runtime", "high", "Use-after-free or over-release"),
    "bad-function-pointer": ("bad-function-pointer", "high", "jumped to 0x123456780"),
    "force-unwrap": ("swift-runtime-failure", "high", "Force unwrap of nil"),
    "index-out-of-range": ("swift-runtime-failure", "high", "Index out of range"),
    "overflow": ("swift-runtime-failure", "high", "Integer overflow"),
    "fatal-error": ("swift-runtime-failure", "high", "Unsupported configuration"),
    "actor-isolation": ("actor-isolation", "high", "ScoreViewModel.startRefreshing() is isolated to the main actor"),
    "nsexception": ("objc-exception", "high", "NSRangeException"),
    "write-constant": ("write-readonly", "high", "a string literal"),
    "corrupt-pointer": ("non-canonical", "medium", "0x4141414141414148"),
    "double-free": ("malloc-error", "high", "double free"),
    "dispatch-sync-main": ("client-bug", "high", "dispatch_sync"),
    "abort": ("abort-deliberate", "medium", "called from abortScenario()"),
}

# Where the user's own code is, for scenarios where that's the point.
EXPECTED_USER_FRAME = {
    "nil-pointer": "nilPointer()",
    "big-enum": "cardBody(_:_:_:depth:)",
    "actor-isolation": "closure #1 in ScoreViewModel.startRefreshing()",
    "nsexception": "nsException()",
    "force-unwrap": "forceUnwrap()",
}

_demo = None


def demo_binary():
    global _demo
    if _demo is None:
        _demo = os.environ.get("WHY_DEMO")
        if not _demo:
            subprocess.run(["swift", "build", "--package-path", DEMO_DIR], check=True,
                           stdout=subprocess.DEVNULL)
            _demo = os.path.join(DEMO_DIR, ".build", "debug", "why-demo")
    return _demo


def lldb(scenario, before_run=(), after_crash=(), after_run=()):
    cmd = [LLDB, "-x", "--batch", "-o", "command script import %s" % PACKAGE]
    for c in before_run:
        cmd += ["-o", c]
    cmd += ["-o", "run"]
    for c in after_run:
        cmd += ["-o", c]
    for c in after_crash:
        cmd += ["-k", c]
    cmd += ["-k", "quit", "--", demo_binary(), scenario]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                          timeout=TIMEOUT)
    return proc.stdout


def json_after(output, command):
    """The JSON object printed by `command` in an lldb transcript."""
    lines = output.splitlines()
    start = lines.index("(lldb) %s" % command) + 1
    body = []
    for line in lines[start:]:
        body.append(line)
        if line == "}":
            break
    return json.loads("\n".join(body))


@unittest.skipUnless(sys.platform == "darwin" and LLDB and shutil.which("swift"), "needs macOS, lldb and swift")
class DemoScenarioTests(unittest.TestCase):
    def test_scenarios(self):
        for scenario, (rule_id, confidence, text) in EXPECTED.items():
            with self.subTest(scenario=scenario):
                out = lldb(scenario, after_crash=["why --json"])
                try:
                    d = json_after(out, "why --json")
                except (ValueError, IndexError):
                    self.fail("no JSON diagnosis in lldb output:\n" + out[-3000:])
                self.assertEqual(d["rule_id"], rule_id, d["verdict"])
                self.assertEqual(d["confidence"], confidence, d["verdict"])
                self.assertIn(text, d["verdict"])
                if scenario in EXPECTED_USER_FRAME:
                    self.assertEqual(d["user_frame"]["display"], EXPECTED_USER_FRAME[scenario])
                self.assertTrue(d["next_steps"])

    def test_plain_text_and_alias(self):
        out = lldb("force-unwrap", after_crash=["diagnose"])
        self.assertIn("why: Swift runtime trap: Force unwrap of nil", out)
        self.assertIn("\nNext steps\n", out)
        self.assertNotIn("\033[", out)

    def test_big_enum_chkstk_evidence(self):
        out = lldb("big-enum", after_crash=["why"])
        self.assertIn("Frame 0 is ___chkstk_darwin", out)
        self.assertIn("from caller's prologue, matches x9", out)

    def test_auto_mode_is_quiet_at_breakpoints(self):
        out = lldb("index-out-of-range", before_run=["why auto on", "breakpoint set -n indexOutOfRange"],
                   after_run=["continue"])
        verdicts = [line for line in out.splitlines() if line.startswith("why: ") and "[confidence" in line]
        self.assertEqual(len(verdicts), 1, out[-3000:])
        self.assertIn("Index out of range", verdicts[0])

    def test_stack_report_at_breakpoint(self):
        out = lldb("recursion-main", before_run=["breakpoint set -n countDown -i 50"],
                   after_run=["why stack", "kill"])
        self.assertIn("Stack usage for thread #1", out)
        self.assertIn("calls  countDown(_:)", out)
        self.assertIn("Pattern   deep recursion: countDown(_:)", out)

    def test_dump_context_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ctx.json")
            lldb("nil-pointer", after_crash=["why dump-context --expect --anonymize -o %s" % path])
            with open(path) as fh:
                data = json.load(fh)
        self.assertEqual(data["expect"]["rule_id"], "nil-deref")
        self.assertEqual(diagnose(CrashContext.from_dict(data["context"])).rule_id, "nil-deref")
        self.assertNotIn(os.path.expanduser("~") + "/", json.dumps(data))


if __name__ == "__main__":
    unittest.main()
