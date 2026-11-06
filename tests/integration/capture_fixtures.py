"""Captures unit-test fixtures from the demo app, so the classifier's unit
tests run on real lldb data without needing a debugger.

    python3 tests/integration/capture_fixtures.py [scenario ...]

Writes tests/unit/fixtures/macos_<scenario>.json. Paths are anonymized: the
repository root becomes /src/lldb-why and your home folder becomes ~.
Review the `expect` block of each new fixture before committing it.
"""

import json
import os
import platform
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_demo  # noqa: E402

# Recursion scenarios produce 11k-174k frames; the unit tests cover them synthetically.
SKIP = {"recursion", "recursion-main"}
OUT = os.path.join(test_demo.ROOT, "tests", "unit", "fixtures")


def capture(scenario):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "ctx.json")
        test_demo.lldb(scenario, after_crash=["why dump-context --expect -o %s" % path])
        with open(path) as fh:
            text = fh.read()
    text = text.replace(test_demo.ROOT, "/src/lldb-why").replace(os.path.expanduser("~"), "~")
    data = json.loads(text)
    rule_id, confidence, verdict_text = test_demo.EXPECTED[scenario]
    data["description"] = "Captured from `why-demo %s` on %s %s (%s)." % (
        scenario, "macOS", platform.mac_ver()[0], platform.machine())
    data["expect"] = {"rule_id": rule_id, "confidence": confidence, "verdict_contains": [verdict_text]}
    if scenario in test_demo.EXPECTED_USER_FRAME:
        data["expect"]["user_frame"] = test_demo.EXPECTED_USER_FRAME[scenario]
    dest = os.path.join(OUT, "macos_%s.json" % scenario.replace("-", "_"))
    with open(dest, "w") as fh:
        json.dump(data, fh, indent=1)
        fh.write("\n")
    return dest


def main(argv):
    scenarios = argv or [s for s in test_demo.EXPECTED if s not in SKIP]
    for scenario in scenarios:
        print("captured", os.path.relpath(capture(scenario), test_demo.ROOT))


if __name__ == "__main__":
    main(sys.argv[1:])
