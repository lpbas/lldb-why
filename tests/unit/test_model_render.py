import json
import unittest

from why.core import CrashContext, analyze_stack, diagnose, render_diagnosis, render_stack
from why.core.text import bad_access_code_text, fmt_size

from builders import bad_access, objc_exception, sigabrt, stack, ABORT_FRAMES
from test_stack import chkstk_ctx


class ModelTests(unittest.TestCase):
    def test_round_trip(self):
        ctx = chkstk_ctx([["mov", "w9, #0x3bd0"]], x9=0x3BD0)
        ctx.exception = objc_exception("NSRangeException", "boom")
        data = json.loads(json.dumps(ctx.to_dict()))
        self.assertEqual(data["stop"]["fault_address"], "0x16f603ff8")
        self.assertEqual(data["registers"]["x9"], "0x3bd0")
        again = CrashContext.from_dict(data)
        self.assertEqual(again.to_dict(), ctx.to_dict())
        self.assertEqual(again.frames[1].sp, 0x16F6070C0)
        self.assertEqual(again.exception.backtrace[3].name, "main")

    def test_unknown_keys_are_ignored(self):
        ctx = CrashContext.from_dict({"stop": {"reason": "signal", "signal": 6, "future": 1}, "later": True})
        self.assertEqual(ctx.stop.signal, 6)


class TextTests(unittest.TestCase):
    def test_sizes(self):
        self.assertEqual(fmt_size(48), "48 B")
        self.assertEqual(fmt_size(15312), "15.0 KB")
        self.assertEqual(fmt_size(8350176), "7.96 MB")

    def test_codes(self):
        self.assertIn("KERN_PROTECTION_FAILURE", bad_access_code_text(2))
        self.assertEqual(bad_access_code_text(0x999), "code=0x999")


class RenderTests(unittest.TestCase):
    def test_plain_text_has_no_ansi(self):
        out = render_diagnosis(diagnose(chkstk_ctx([["mov", "w9, #0x3bd0"]], x9=0x3BD0)))
        self.assertNotIn("\033[", out)
        first = out.splitlines()[0]
        self.assertTrue(first.startswith("why: Stack overflow"))
        self.assertIn("[confidence: high]", first)
        for section in ("Evidence", "Where", "Stack", "Notes", "Next steps"):
            self.assertIn("\n%s\n" % section, out)
        self.assertIn("MemoryLayout<EndContent?>.size", out)

    def test_color(self):
        out = render_diagnosis(diagnose(sigabrt(stack(*(ABORT_FRAMES + [("main", "demo")])))), color=True)
        self.assertIn("\033[1m", out)

    def test_stack_report(self):
        out = render_stack(analyze_stack(chkstk_ctx([["mov", "w9, #0x3bd0"]], x9=0x3BD0)))
        self.assertIn("Used      7.96 MB of 7.98 MB (99.7%) across 76 frames", out)
        self.assertIn("requested 15.0 KB (15312 bytes; caller's prologue, matches x9)", out)
        self.assertIn("Largest frames", out)
        self.assertIn("x73", out)
        self.assertIn("Frames: 74 yours (7.96 MB), 0 SwiftUI (0 B), 2 system (0 B)", out)

    def test_verdict_for_bad_access_is_one_line(self):
        out = render_diagnosis(diagnose(bad_access(stack(("main", "demo")), 0x28)))
        self.assertNotIn("\n", out.splitlines()[0])


if __name__ == "__main__":
    unittest.main()
