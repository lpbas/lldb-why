"""Runs every tests/unit/fixtures/*.json through the classifier.

Fixture format:
    {
      "description": "what this is and where it came from",
      "expect": {
        "rule_id": "stack-overflow",
        "confidence": "high",                # optional
        "verdict_contains": ["..."],         # optional
        "user_frame": "deepChain(_:_:)",     # optional, display name
        "output_contains": ["..."]           # optional, checked against the rendered text
      },
      "context": { ...CrashContext.to_dict()... }
    }

`why dump-context --expect` in lldb writes this format from a live crash.
"""

import glob
import json
import os
import unittest

from why.core import CrashContext, diagnose, render_diagnosis

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class FixtureTests(unittest.TestCase):
    def test_fixtures(self):
        paths = sorted(glob.glob(os.path.join(FIXTURES, "*.json")))
        self.assertTrue(paths, "no fixtures found")
        for path in paths:
            with self.subTest(fixture=os.path.basename(path)):
                with open(path) as fh:
                    data = json.load(fh)
                expect = data["expect"]
                d = diagnose(CrashContext.from_dict(data["context"]))
                self.assertEqual(d.rule_id, expect["rule_id"], d.verdict)
                if "confidence" in expect:
                    self.assertEqual(d.confidence, expect["confidence"])
                for text in expect.get("verdict_contains", []):
                    self.assertIn(text, d.verdict)
                if "user_frame" in expect:
                    self.assertIsNotNone(d.user_frame)
                    self.assertEqual(d.user_frame.name, expect["user_frame"])
                rendered = render_diagnosis(d)
                for text in expect.get("output_contains", []):
                    self.assertIn(text, rendered)


if __name__ == "__main__":
    unittest.main()
