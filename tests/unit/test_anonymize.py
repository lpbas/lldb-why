import glob
import json
import os
import unittest

from why.core import CrashContext, diagnose, render_diagnosis
from why.core.anonymize import anonymize, leftovers
from why.core.model import LanguageException, Region, ThreadInfo
from why.core.text import clean

from builders import bad_access, instrumentation, objc_exception, sigabrt, stack, ABORT_FRAMES

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
HOME = "/Users/someone"


def load(path):
    with open(path) as fh:
        return CrashContext.from_dict(json.load(fh)["context"])


def dump(ctx):
    return json.dumps(ctx.to_dict(), ensure_ascii=False)


class FixtureTests(unittest.TestCase):
    def test_every_fixture(self):
        """Same classification, no original name left, input untouched, deterministic."""
        for path in sorted(glob.glob(os.path.join(FIXTURES, "*.json"))):
            with self.subTest(fixture=os.path.basename(path)):
                ctx = load(path)
                before = dump(ctx)
                out, report, originals = anonymize(ctx, home=HOME)
                self.assertEqual(dump(ctx), before, "input was modified")
                d0, d1 = diagnose(ctx), diagnose(out)
                self.assertEqual((d0.rule_id, d0.confidence), (d1.rule_id, d1.confidence))
                text = dump(out)
                self.assertEqual(leftovers(text, originals), [])
                self.assertEqual(text, dump(anonymize(ctx, home=HOME)[0]))
                self.assertTrue(report.lines())

    def test_real_ios_case(self):
        path = os.path.join(FIXTURES, "ios_swiftui_enum_copy.json")
        ctx = load(path)
        out, _, _ = anonymize(ctx)
        text = dump(out)
        for name in ("SampleApp", "DesignKit", "SettingsView", "ListRow", "_ListSection", "rowsSection", "row3",
                     "/src/"):
            self.assertNotIn(name, text)
        d = diagnose(out)
        self.assertRegex(d.verdict, r"^Stack overflow: 8 of your frames take 828\.9 KB of the 1008\.0 KB stack "
                                    r"\(largest: Type\d+\.body\.getter, 322\.8 KB\)$")
        # Apple frames, addresses and sizes are kept.
        self.assertEqual([f.sp for f in out.frames], [f.sp for f in ctx.frames])
        self.assertEqual([f.function for f in out.frames if f.module == "AttributeGraph"],
                         [f.function for f in ctx.frames if f.module == "AttributeGraph"])
        self.assertTrue(all(f.module_path.startswith("/redacted/") for f in out.frames if f.module.endswith(".debug.dylib")))
        self.assertEqual(out.registers, ctx.registers)


class LeakTests(unittest.TestCase):
    APP = "/Users/someone/Projects/AcmeBank/build/AcmeBank.app/AcmeBank"

    def ctx(self):
        frames = stack(
            ("__pthread_kill", "libsystem_kernel.dylib"),
            ("ViewGraph.updateOutputs(at:)", "SwiftUICore",
             {"function": "SwiftUI.ModifiedContent<AcmeBank.TransferView, SwiftUI._PaddingLayout>.body.getter"}),
            ("TransferView.confirm(amount:)", "AcmeBank",
             {"function": "AcmeBank.TransferView.confirm(amount: Swift.Double) -> ()",
              "file": "/Users/someone/Projects/AcmeBank/Sources/Transfers/TransferView.swift", "line": 42}),
            ("start", "dyld"))
        for f in frames:
            if f.module == "AcmeBank":
                f.module_path = self.APP
        ctx = bad_access(frames, 0x10,
                         thread=ThreadInfo(index=3, name="AcmeSyncWorker", queue="com.acmebank.sync", is_main=False),
                         pc_region=Region(base=0x100000000, end=0x100100000, image=self.APP, section="__TEXT.__text"))
        ctx.main_executable = self.APP
        return ctx

    def test_user_names_everywhere_are_renamed(self):
        out, report, originals = anonymize(self.ctx(), home=HOME)
        text = dump(out)
        for name in ("AcmeBank", "TransferView", "confirm", "amount", "Transfers", "Projects", "someone",
                     "AcmeSyncWorker", "acmebank"):
            self.assertNotIn(name, text)
        self.assertEqual(leftovers(text, originals), [])
        # The user's type inside a SwiftUI generic is renamed; Apple names stay.
        self.assertRegex(out.frames[1].function, r"^SwiftUI\.ModifiedContent<Module\d+\.Type\d+, SwiftUI\._PaddingLayout>\.body\.getter$")
        self.assertEqual(out.frames[1].display, "ViewGraph.updateOutputs(at:)")
        self.assertTrue(out.frames[2].file.startswith("/redacted/") and out.frames[2].file.endswith(".swift"))
        self.assertEqual(out.pc_region.section, "__TEXT.__text")
        self.assertEqual((out.thread.name, out.thread.queue), ("<redacted>", "<redacted>"))
        self.assertEqual(report.modules, 1)

    def test_messages_keep_only_known_phrases(self):
        frames = stack(("swift_runtime_on_report", "libswiftCore.dylib"), ("main", "demo"))
        ctx = instrumentation(frames, "Fatal error: Could not load account 1234 for jane@example.com")
        out, report, _ = anonymize(ctx)
        self.assertEqual(out.stop.instrumentation_message, "Fatal error: <redacted>")
        self.assertNotIn("jane", dump(out))
        self.assertEqual(report.messages, 1)

        ctx = instrumentation(frames, "Fatal error: Index out of range")
        out, _, _ = anonymize(ctx)
        self.assertEqual(out.stop.instrumentation_message, "Fatal error: Index out of range")
        self.assertEqual(diagnose(out).verdict, diagnose(ctx).verdict)

    def test_exception_reason(self):
        exc = objc_exception("NSInvalidArgumentException",
                             "-[AcmeAccount setEmail:]: unrecognized selector sent to instance 0x6000 (jane@example.com)")
        out, _, _ = anonymize(sigabrt(stack(*ABORT_FRAMES), exception=exc))
        self.assertEqual(out.exception.name, "NSInvalidArgumentException")
        self.assertEqual(out.exception.reason, "unrecognized selector")
        self.assertNotIn("jane", dump(out))
        self.assertNotIn("Acme", dump(out))

        custom = LanguageException(language="cpp", name="acme::LedgerError", reason="balance -12 for jane")
        out, _, _ = anonymize(sigabrt(stack(*ABORT_FRAMES), exception=custom))
        self.assertNotIn("acme", out.exception.name)
        self.assertEqual(out.exception.reason, "<redacted>")


class CleanTests(unittest.TestCase):
    def test_control_characters_are_replaced(self):
        self.assertEqual(clean("ok\x1b]52;c;ZXZpbA==\x07name‮"), "ok?]52;c;ZXZpbA==?name?")
        self.assertEqual(clean("tab\tnew\nline"), "tab\tnew\nline")

    def test_render_strips_escape_sequences_from_app_text(self):
        frames = stack(("swift_runtime_on_report", "libswiftCore.dylib"), ("main", "demo"))
        d = diagnose(instrumentation(frames, "Fatal error: \x1b[2J\x1b]0;pwned\x07"))
        out = render_diagnosis(d)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertIn("\033[1m", render_diagnosis(d, color=True))   # our own styling still works


if __name__ == "__main__":
    unittest.main()
