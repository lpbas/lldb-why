import unittest

from why.core.model import CrashContext, Region, StopInfo
from why.core.stack import analyze_stack, prologue_frame_size

from builders import MAIN_STACK, bad_access, frame, stack


class PrologueTests(unittest.TestCase):
    def test_arm64_mov(self):
        # Verbatim from `outlined init with copy of EndContent?` on arm64 macOS 26
        ins = [["stp", "x28, x27, [sp, #-0x60]!"], ["stp", "x29, x30, [sp, #0x50]"], ["add", "x29, sp, #0x50"],
               ["mov", "w9, #0x3bd0               ; =15312 "], ["adrp", "x16, 98"], ["ldr", "x16, [x16, #0x3c8]"]]
        self.assertEqual(prologue_frame_size(ins, "arm64"), 15312)

    def test_arm64_movz_movk(self):
        ins = [["movz", "x9, #0x2, lsl #16"], ["movk", "x9, #0x1a0"]]
        self.assertEqual(prologue_frame_size(ins, "arm64"), 0x201A0)

    def test_arm64_overwritten(self):
        ins = [["mov", "w9, #0x3bd0"], ["ldr", "x9, [x0]"]]
        self.assertIsNone(prologue_frame_size(ins, "arm64"))

    def test_arm64_store_does_not_clobber(self):
        ins = [["mov", "w9, #0x2000"], ["stp", "x9, x10, [sp]"]]
        self.assertEqual(prologue_frame_size(ins, "arm64e"), 0x2000)

    def test_x86_64(self):
        self.assertEqual(prologue_frame_size([["movl", "$0x5a10, %eax"]], "x86_64"), 0x5A10)
        self.assertEqual(prologue_frame_size([["mov", "eax, 0x5a10"]], "x86_64"), 0x5A10)
        self.assertIsNone(prologue_frame_size([["pushq", "%rbp"]], "x86_64"))


def chkstk_ctx(prologue=None, x9=None):
    # Real values from the oversized-enum probe on an 8 MB main thread
    frames = [frame(0, "___chkstk_darwin", "libsystem_pthread.dylib", sp=0x16F6070C0),
              frame(1, "outlined init with copy of EndContent?", "demo", sp=0x16F6070C0,
                    function="outlined init with copy of Swift.Optional<demo.EndContent>")]
    sp = 0x16F607120
    for i in range(2, 75):
        frames.append(frame(i, "deepChain(_:_:)", "demo", sp=sp, file="/src/BigEnum.swift", line=23))
        sp += 115824
    frames.append(frame(75, "start", "dyld", sp=0x16FDFDAA0))
    registers = {"x9": x9} if x9 is not None else {}
    return bad_access(frames, 0x16F603FF8, code=2, registers=registers, caller_prologue=prologue or [])


class StackReportTests(unittest.TestCase):
    def test_chkstk_confirmed_by_register(self):
        r = analyze_stack(chkstk_ctx([["mov", "w9, #0x3bd0"]], x9=0x3BD0))
        self.assertEqual(r.chkstk.requested, 15312)
        self.assertTrue(r.chkstk.confirmed)
        self.assertEqual(r.chkstk.available, 0x16F6070C0 - 0x16F604000)
        self.assertEqual(r.pattern, "large-frames")
        self.assertEqual(r.by_function[0].name, "deepChain(_:_:)")
        self.assertEqual(r.by_function[0].count, 73)

    def test_chkstk_register_only(self):
        r = analyze_stack(chkstk_ctx(x9=0x3BD0))
        self.assertEqual(r.chkstk.requested, 15312)
        self.assertFalse(r.chkstk.confirmed)
        self.assertEqual(r.chkstk.source, "x9 register")

    def test_chkstk_register_too_small_is_ignored(self):
        # inside the probing loop x9 has been decremented below what was available
        r = analyze_stack(chkstk_ctx(x9=0x100))
        self.assertIsNone(r.chkstk.requested)
        self.assertIn("more than", r.chkstk.source)

    def test_usage_and_percent(self):
        r = analyze_stack(chkstk_ctx())
        self.assertEqual(r.used, 0x16FDFDAA0 - 0x16F6070C0)
        self.assertAlmostEqual(r.percent, 99.7, places=1)
        self.assertEqual(r.largest[0].size, 115824)
        self.assertEqual(r.counts["user"], 74)
        self.assertEqual(r.counts["system"], 2)

    def test_mutual_recursion_cycle(self):
        frames = []
        sp = 0x16F604100
        for i in range(600):
            frames.append(frame(i, "isEven(_:)" if i % 2 == 0 else "isOdd(_:)", "demo", sp=sp))
            sp += 64
        frames.append(frame(600, "main", "demo", sp=sp))
        r = analyze_stack(bad_access(frames, 0x16F603FF0, code=2))
        self.assertEqual(r.pattern, "infinite-recursion")
        self.assertEqual(sorted(r.cycle), ["isEven(_:)", "isOdd(_:)"])
        self.assertEqual(r.cycle_frame_size, 128)

    def test_swiftui_only_cycles_are_not_recursion(self):
        specs = []
        for _ in range(100):
            specs += [("ModifiedContent.body", "SwiftUICore"), ("AG::Graph::update", "AttributeGraph")]
        r = analyze_stack(bad_access(stack(*specs), 0x16F603FF0, code=2))
        self.assertEqual(r.cycle_reps, 0)
        self.assertEqual(r.counts["swiftui"], 200)

    def test_truncated_walk_uses_region_end(self):
        ctx = CrashContext(stop=StopInfo(reason="breakpoint"), frames=stack(("a", "demo"), ("b", "demo")),
                           total_frames=50000, stack_region=MAIN_STACK)
        r = analyze_stack(ctx)
        self.assertTrue(r.approximate)
        self.assertEqual(r.used, MAIN_STACK.end - 0x16FDFB000)
        self.assertEqual(r.total_frames, 50000)

    def test_no_region(self):
        ctx = CrashContext(stop=StopInfo(reason="breakpoint"), frames=stack(("a", "demo"), ("b", "demo")))
        r = analyze_stack(ctx)
        self.assertIsNone(r.percent)
        self.assertEqual(r.used, 0x40)


if __name__ == "__main__":
    unittest.main()
