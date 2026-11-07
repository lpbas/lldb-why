import unittest

from why.core import diagnose
from why.core.engine import category_of
from why.core.model import CrashContext, LayoutPart, Region, StopInfo, ThreadInfo, ValueLayout

from builders import (ABORT_FRAMES, MAIN_STACK, MASK, bad_access, frame, instrumentation, objc_exception, sigabrt,
                      stack, trap)


class BadAccessTests(unittest.TestCase):
    def test_nil_field_offset(self):
        frames = stack(("swift::metadataimpl::ValueWitnesses<...>::initializeWithCopy", "libswiftCore.dylib"),
                       ("main", "demo", {"file": "/src/main.swift", "line": 42}), ("start", "dyld"))
        d = diagnose(bad_access(frames, 0x28))
        self.assertEqual(d.rule_id, "nil-deref")
        self.assertIn("offset 0x28 of a nil pointer", d.verdict)
        self.assertEqual(d.confidence, "high")
        self.assertEqual(d.user_frame.name, "main")
        self.assertIn("main.swift:42", d.where[0])
        self.assertTrue(any("KERN_INVALID_ADDRESS" in e for e in d.evidence))

    def test_large_pagezero_address_is_bad_pointer(self):
        d = diagnose(bad_access(stack(("main", "demo"), ("start", "dyld")), 0x12345678))
        self.assertEqual(d.rule_id, "nil-deref")
        self.assertIn("__PAGEZERO", d.verdict)
        self.assertEqual(d.confidence, "medium")

    def test_garbage_function_pointer(self):
        frames = [frame(0, "", module="", pc=0x123456780, function="")] + stack(("main", "demo"), ("start", "dyld"))[0:2]
        frames[1].index, frames[2].index = 1, 2
        d = diagnose(bad_access(frames, 0x123456780, fault_region=Region(base=0x123456780, end=0x16BE00000)))
        self.assertEqual(d.rule_id, "bad-function-pointer")
        self.assertIn("jumped to 0x123456780", d.verdict)
        self.assertEqual(d.user_frame.index, 1)

    def test_write_to_string_literal(self):
        region = Region(base=0x100004000, end=0x100074000, readable=True, executable=True, mapped=True,
                        image="demo", section="__TEXT.__cstring")
        d = diagnose(bad_access(stack(("main", "demo"), ("start", "dyld")), 0x10006F896, code=2, fault_region=region))
        self.assertEqual(d.rule_id, "write-readonly")
        self.assertIn("a string literal", d.verdict)
        self.assertIn("__TEXT.__cstring of demo", d.verdict)

    def test_non_canonical_pointer(self):
        d = diagnose(bad_access(stack(("main", "demo"), ("start", "dyld")), 0x4141414141414148))
        self.assertEqual(d.rule_id, "non-canonical")
        self.assertEqual(d.confidence, "medium")
        self.assertTrue(any("isn't arm64e" in n for n in d.notes))

    def test_pointer_auth_failure_description(self):
        ctx = bad_access(stack(("main", "demo"), ("start", "dyld")), 0x2000000102345678, arch="arm64e")
        ctx.stop.description += " (possible pointer authentication failure)"
        d = diagnose(ctx)
        self.assertEqual(d.rule_id, "non-canonical")
        self.assertIn("Pointer authentication failure", d.verdict)
        self.assertEqual(d.confidence, "high")

    def test_over_release_in_swift_runtime(self):
        # Real case: Unmanaged over-release crashes at NULL-12 inside _swift_release_dealloc
        frames = stack(("_swift_release_dealloc", "libswiftCore.dylib"),
                       ("bool swift::RefCounts<...>::doDecrementSlow<(swift::PerformDeinit)1>", "libswiftCore.dylib"),
                       ("main", "demo"), ("start", "dyld"))
        d = diagnose(bad_access(frames, 0xFFFFFFFFFFFFFFF4))
        self.assertEqual(d.rule_id, "refcount-runtime")
        self.assertIn("Use-after-free or over-release", d.verdict)

    def test_objc_msgsend_to_dead_object(self):
        frames = stack(("objc_msgSend", "libobjc.A.dylib"), ("-[Foo bar]", "demo"), ("start", "dyld"))
        d = diagnose(bad_access(frames, 0x7000000010))
        self.assertEqual(d.rule_id, "refcount-runtime")
        self.assertIn("deallocated or invalid Objective-C object", d.verdict)

    def test_scribble_patterns(self):
        frames = stack(("main", "demo"), ("start", "dyld"))
        self.assertIn("freed memory", diagnose(bad_access(frames, 0x5555555555555565)).verdict)
        d = diagnose(bad_access(frames, 0xAAAAAAAAAAAAAABA))
        self.assertEqual(d.rule_id, "malloc-scribble")
        self.assertIn("uninitialized", d.verdict)

    def test_heap_region(self):
        region = Region(base=0x70D000000, end=0x70D400000, readable=False, writable=False, mapped=True,
                        type="heap,malloc-small")
        d = diagnose(bad_access(stack(("main", "demo"), ("start", "dyld")), 0x70D020090, code=2, fault_region=region))
        self.assertEqual(d.rule_id, "heap-address")

    def test_unclassified_bad_access(self):
        region = Region(base=0x300000000, end=0x300004000, readable=True, writable=True, mapped=True)
        d = diagnose(bad_access(stack(("main", "demo"), ("start", "dyld")), 0x300000010, code=1, fault_region=region))
        self.assertEqual(d.rule_id, "bad-access-unclassified")
        self.assertEqual(d.confidence, "low")


class StackOverflowTests(unittest.TestCase):
    def test_infinite_recursion_on_secondary_thread(self):
        # Real case: 512 KB thread, recurse(_:) at 48 B per frame, sp already in the 16 KB guard
        region = Region(base=0x16FE04000, end=0x16FE88000, readable=True, writable=True, mapped=True, type="stack")
        frames = []
        sp = 0x16FE03FE0
        for i in range(11165):
            frames.append(frame(i, "recurse(_:)", "demo", sp=sp, function="demo.recurse(Swift.Int) -> Swift.Int"))
            sp += 48
        frames.append(frame(11165, "__NSThread__start__", "Foundation", sp=sp))
        frames.append(frame(11166, "_pthread_start", "libsystem_pthread.dylib", sp=sp + 608))
        ctx = bad_access(frames, 0x16FE03FF8, code=2, stack_region=region,
                         thread=ThreadInfo(index=2, is_main=False))
        d = diagnose(ctx)
        self.assertEqual(d.rule_id, "stack-overflow")
        self.assertEqual(d.confidence, "high")
        self.assertIn("infinite recursion in recurse(_:)", d.verdict)
        self.assertTrue(any("below the stack's base" in e for e in d.evidence))
        self.assertTrue(any("512 KB" in n for n in d.notes))  # secondary thread note

    @staticmethod
    def _real_ios_case(optimized=None, copied_value=None):
        """Shaped on a real iOS crash (frame sizes, x9, stack size and headroom
        from its `why stack` report): a few huge SwiftUI body frames of the
        app's own code fill the 1 MB main thread, and the outlined copy helper
        for ListRow.Trailing? hits the guard page."""
        region = Region(base=0x16D2D0000, end=0x16D3CC000, readable=True, writable=True, mapped=True, type="stack")
        app = "App.debug.dylib"
        layout = [
            ("___chkstk_darwin", "libsystem_pthread.dylib", 16, {}),
            ("outlined init with copy of ListRow.Trailing?", app, 96,
             {"function": "outlined init with copy of Swift.Optional<App.ListRow.Trailing>"}),
            ("ListRow.init(label:leading:trailing:action:)", app, 14438, {"file": "ListRow.swift", "line": 211}),
            ("SettingsView.row3.getter", app, 81100, {}),
            ("closure #1 in SettingsView.rowsSection.getter", app, 316928, {}),
            ("closure #1 in _ListSection.body.getter", app, 105472, {}),
            ("VStack.init(alignment:spacing:content:)", "SwiftUI", 300, {}),
            ("_ListSection.body.getter", app, 330547, {"file": "_ListSection.swift", "line": 23}),
            ("ViewBodyAccessor.updateBody(of:changed:)", "SwiftUICore", 400, {}),
            ("closure #1 in ViewBodyAccessor.updateBody(of:changed:)", "SwiftUICore", 109363, {}),
        ]
        layout += [("AG::Graph::UpdateStack::update()", "AttributeGraph", 1000, {})] * 40
        layout += [("__CFRunLoopRun", "CoreFoundation", 800, {})] * 5 + [("start", "dyld", 0, {})]
        frames, sp = [], region.base + 21600
        for i, (name, module, size, kw) in enumerate(layout):
            if module == app:
                kw = dict(kw, function=kw.get("function", "App." + name))
            f = frame(i, name, module, sp=sp, **kw)
            f.optimized = optimized if module == app else None
            frames.append(f)
            sp += size
        ctx = bad_access(frames, 0x16D2CFFF8, code=2, stack_region=region, platform="ios",
                         registers={"x9": 24960}, caller_prologue=[["mov", "w9, #0x6180"]],
                         copied_value=copied_value)
        return diagnose(ctx)

    def test_real_ios_case_names_your_frames(self):
        d = self._real_ios_case()
        self.assertEqual(d.rule_id, "stack-overflow")
        self.assertRegex(d.verdict, r"^Stack overflow: 6 of your frames take 828\.7 KB of the 1008\.0 KB stack "
                                    r"\(largest: _ListSection\.body\.getter, 322\.8 KB\)$")
        self.assertIn("Biggest consumer: _ListSection.body.getter, 322.8 KB in one call", d.evidence)
        self.assertTrue(any("24960 bytes, from caller's prologue, matches x9" in e for e in d.evidence))
        self.assertTrue(any(n.startswith("This is a Debug build") for n in d.notes))  # from App.debug.dylib
        self.assertIn("MemoryLayout<ListRow.Trailing?>.size", d.next_steps[0])
        self.assertEqual(d.user_frame.name, "ListRow.init(label:leading:trailing:action:)")

    def test_real_ios_case_with_measured_type(self):
        value = ValueLayout(type="Swift.Optional<App.ListRow.Trailing>", size=7673, variable="end",
                            frame_index=2, parts=[  # case and payload names are made up
                                LayoutPart(name="stats", type="(App.MatchStats, title: Swift.String)",
                                           size=7672, is_case=True),
                                LayoutPart(name="0", type="App.MatchStats", size=7656)])
        d = self._real_ios_case(copied_value=value)
        self.assertIn("Size: ListRow.Trailing? is 7.5 KB (7673 bytes, measured on `end` in frame #2). "
                      "Almost all of it is case .stats: `.stats.0` is MatchStats, 7.5 KB", d.evidence)
        self.assertTrue(any("every ListRow.Trailing? is 7.5 KB because of case .stats" in n for n in d.notes))
        self.assertTrue(d.next_steps[0].startswith("Box the payload of case .stats: write `indirect case stats(...)`, "
                                                   "or keep MatchStats in a final class"))
        self.assertIn("should drop well below 7673", d.next_steps[0])

    def test_optimized_build_has_no_debug_note(self):
        d = self._real_ios_case(optimized=True)
        self.assertFalse(any(n.startswith("This is a Debug build") for n in d.notes))

    def test_guard_page_fault_alone_is_overflow(self):
        frames = stack(("deep(_:)", "demo"), ("main", "demo"), ("start", "dyld"), sp0=0x16F604010, step=0x3FFF00)
        d = diagnose(bad_access(frames, 0x16F603FF0, code=2))
        self.assertEqual(d.rule_id, "stack-overflow")

    def test_fault_far_below_stack_is_not_overflow(self):
        d = diagnose(bad_access(stack(("main", "demo"), ("start", "dyld")), 0x16F504000, code=1))
        self.assertNotEqual(d.rule_id, "stack-overflow")


class TrapTests(unittest.TestCase):
    def test_actor_isolation(self):
        # Real case: @MainActor closure passed to a C API that calls it on a global queue
        frames = stack(("_dispatch_assert_queue_fail", "libdispatch.dylib"),
                       ("dispatch_assert_queue$V2.cold.1", "libdispatch.dylib"),
                       ("dispatch_assert_queue", "libdispatch.dylib"),
                       ("_swift_task_checkIsolatedSwift", "libswift_Concurrency.dylib"),
                       ("swift_task_isCurrentExecutorWithFlagsImpl(swift::SerialExecutorRef, swift::swift_task_is_current_executor_flag)",
                        "libswift_Concurrency.dylib"),
                       ("closure #1 in ViewModel.start()", "demo", {"file": "Isolation.swift", "line": 12}),
                       ("thunk for @escaping @callee_guaranteed () -> ()", "demo"),
                       ("_dispatch_call_block_and_release", "libdispatch.dylib"),
                       ("_dispatch_client_callout", "libdispatch.dylib"))
        ctx = trap(frames, "EXC_BREAKPOINT (code=1, subcode=0x1804f14fc)",
                   thread=ThreadInfo(index=2, queue="com.apple.root.default-qos"))
        d = diagnose(ctx)
        self.assertEqual(d.rule_id, "actor-isolation")
        self.assertIn("closure #1 in ViewModel.start() is isolated to the main actor", d.verdict)
        self.assertIn("com.apple.root.default-qos", d.verdict)
        self.assertTrue(any("_dispatch_call_block_and_release" in e for e in d.evidence))
        self.assertTrue(any("swift_task_isCurrentExecutorWithFlagsImpl" in e for e in d.evidence))
        self.assertTrue(any("inferred @MainActor" in n for n in d.notes))

    def test_force_unwrap_debug_build(self):
        frames = stack(("_swift_runtime_on_report", "libswiftCore.dylib"),
                       ("_swift_stdlib_reportFatalErrorInFile", "libswiftCore.dylib"),
                       ("closure #1 in closure #1 in _assertionFailure(_:_:file:line:flags:)", "libswiftCore.dylib"),
                       ("_assertionFailure(_:_:file:line:flags:)", "libswiftCore.dylib"),
                       ("main", "demo"), ("start", "dyld"))
        d = diagnose(instrumentation(frames, "Fatal error: Unexpectedly found nil while unwrapping an Optional value"))
        self.assertEqual(d.rule_id, "swift-runtime-failure")
        self.assertIn("Force unwrap of nil", d.verdict)
        self.assertEqual(d.user_frame.name, "main")

    def test_index_out_of_range_optimized_build(self):
        frames = stack(("Swift runtime failure: Index out of range", "demo", {"inlined": True}),
                       ("specialized Array._checkSubscript(_:wasNativeTypeChecked:)", "demo", {"inlined": True}),
                       ("specialized Array.subscript.getter", "demo", {"inlined": True}),
                       ("main", "demo"), ("start", "dyld"))
        d = diagnose(trap(frames, "Swift runtime failure: Index out of range"))
        self.assertEqual(d.rule_id, "swift-runtime-failure")
        self.assertIn("Index out of range", d.verdict)
        # "specialized ..." stdlib code inlined into the user binary still counts as the user's binary
        self.assertNotIn("Swift runtime failure", d.user_frame.name)

    def test_custom_fatal_error(self):
        frames = stack(("_swift_runtime_on_report", "libswiftCore.dylib"), ("main", "demo"), ("start", "dyld"))
        d = diagnose(instrumentation(frames, "Fatal error: custom message"))
        self.assertIn('fatalError() stopped the program: "custom message"', d.verdict)

    def test_overflow_inline_trap(self):
        frames = stack(("Swift runtime failure: arithmetic overflow", "demo", {"inlined": True}),
                       ("main", "demo"), ("start", "dyld"))
        d = diagnose(trap(frames, "Swift runtime failure: arithmetic overflow"))
        self.assertIn("Integer overflow", d.verdict)

    def test_trap_without_message_in_user_code(self):
        d = diagnose(trap(stack(("main", "demo"), ("start", "dyld")), "EXC_BREAKPOINT (code=1, subcode=0x100001000)"))
        self.assertEqual(d.rule_id, "swift-trap-unknown")

    def test_dispatch_sync_deadlock(self):
        frames = stack(("__DISPATCH_WAIT_FOR_QUEUE__", "libdispatch.dylib"), ("_dispatch_sync_f_slow", "libdispatch.dylib"),
                       ("main", "demo"), ("start", "dyld"))
        d = diagnose(trap(frames, "EXC_BREAKPOINT (code=1, subcode=0x1)"))
        self.assertEqual(d.rule_id, "client-bug")
        self.assertIn("dispatch_sync", d.verdict)


class AbortTests(unittest.TestCase):
    def test_objc_exception(self):
        frames = stack(*(ABORT_FRAMES + [("__abort_message", "libc++abi.dylib"), ("_objc_terminate()", "libobjc.A.dylib"),
                                          ("std::__terminate(void (*)())", "libc++abi.dylib"),
                                          ("objc_exception_throw", "libobjc.A.dylib"), ("main", "demo")]))
        exc = objc_exception("NSRangeException", "*** -[__NSSingleObjectArrayI objectAtIndex:]: index 5 beyond bounds [0 .. 0]",
                             throw_site="loadItems()")
        d = diagnose(sigabrt(frames, exc))
        self.assertEqual(d.rule_id, "objc-exception")
        self.assertIn("NSRangeException", d.verdict)
        self.assertIn("index 5 beyond bounds", d.verdict)
        self.assertEqual(d.user_frame.name, "loadItems()")
        self.assertTrue(any("Thrown from" in e and "loadItems()" in e for e in d.evidence))
        self.assertTrue(d.notes)

    def test_objc_exception_without_details(self):
        frames = stack(*(ABORT_FRAMES + [("objc_exception_throw", "libobjc.A.dylib"), ("main", "demo")]))
        d = diagnose(sigabrt(frames))
        self.assertEqual(d.rule_id, "objc-exception")
        self.assertIn("weren't readable", d.verdict)

    def test_cxx_exception(self):
        frames = stack(*(ABORT_FRAMES + [("std::__terminate(void (*)())", "libc++abi.dylib"),
                                          ("__cxa_throw", "libc++abi.dylib"), ("parse()", "demo")]))
        self.assertEqual(diagnose(sigabrt(frames)).rule_id, "cxx-exception")

    def test_double_free(self):
        frames = stack(*(ABORT_FRAMES + [("malloc_vreport", "libsystem_malloc.dylib"),
                                          ("___BUG_IN_CLIENT_OF_LIBMALLOC_POINTER_BEING_FREED_WAS_NOT_ALLOCATED", "libsystem_malloc.dylib"),
                                          ("main", "demo")]))
        d = diagnose(sigabrt(frames))
        self.assertEqual(d.rule_id, "malloc-error")
        self.assertIn("double free", d.verdict)

    def test_double_free_trap_in_mfm_free(self):
        # Real case on macOS 26: free() twice traps (EXC_BREAKPOINT) inside libsystem_malloc
        frames = stack(("mfm_free.cold.4", "libsystem_malloc.dylib"), ("mfm_free", "libsystem_malloc.dylib"),
                       ("doubleFree()", "demo"), ("main", "demo"))
        d = diagnose(trap(frames, "EXC_BREAKPOINT (code=1, subcode=0x1804aa058)"))
        self.assertEqual(d.rule_id, "malloc-error")
        self.assertIn("double free", d.verdict)
        self.assertEqual(d.user_frame.name, "doubleFree()")

    def test_deliberate_abort(self):
        d = diagnose(sigabrt(stack(*(ABORT_FRAMES + [("main", "demo"), ("start", "dyld")]))))
        self.assertEqual(d.rule_id, "abort-deliberate")
        self.assertIn("called from main", d.verdict)
        self.assertEqual(d.user_frame.name, "main")


class OtherTests(unittest.TestCase):
    def test_breakpoint_is_not_a_crash(self):
        ctx = CrashContext(stop=StopInfo(reason="breakpoint", description="breakpoint 1.1"),
                           frames=stack(("main", "demo")))
        d = diagnose(ctx)
        self.assertEqual(d.rule_id, "not-a-crash")
        self.assertIn("breakpoint 1.1", d.verdict)

    def test_exc_guard(self):
        ctx = CrashContext(stop=StopInfo(reason="exception", exc_type=12, description="EXC_GUARD"),
                           frames=stack(("close", "libsystem_kernel.dylib"), ("main", "demo")))
        d = diagnose(ctx)
        self.assertEqual(d.rule_id, "resource")
        self.assertTrue(any("guarded resource" in e for e in d.evidence))

    def test_categories(self):
        self.assertEqual(category_of(StopInfo(exc_type=1)), "bad_access")
        self.assertEqual(category_of(StopInfo(reason="signal", signal=11)), "bad_access")
        self.assertEqual(category_of(StopInfo(exc_type=2)), "trap")
        self.assertEqual(category_of(StopInfo(reason="instrumentation")), "trap")
        self.assertEqual(category_of(StopInfo(reason="signal", signal=6)), "abort")
        self.assertEqual(category_of(StopInfo(reason="signal", signal=17)), "not-a-crash")  # SIGSTOP
        self.assertEqual(category_of(StopInfo(reason="trace")), "not-a-crash")

    def test_every_diagnosis_has_steps(self):
        for ctx in (bad_access(stack(("main", "demo")), 0x10),
                    sigabrt(stack(*(ABORT_FRAMES + [("main", "demo")])))):
            self.assertTrue(diagnose(ctx).next_steps)


if __name__ == "__main__":
    unittest.main()
