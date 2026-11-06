"""The rule table. Rules are checked top to bottom, and the first one whose
category matches the stop and whose `when` predicate is true wins, so put
specific signatures above general ones. Each category ends with a catch-all.

To add a rule, see CONTRIBUTING.md. In short: add a Rule(...) entry in the
right place, then add a fixture under tests/unit/fixtures and a test.
"""

import re

from . import frames as F
from .engine import Rule
from .stack import is_chkstk
from .text import Steps, fmt_size, EXC_EXPLANATIONS, EXC_NAMES, SIGNAL_EXPLANATIONS

# --- symbol groups ------------------------------------------------------------

REFCOUNT_RUNTIME = [
    r"^swift_(retain|release|unknownObjectRe|bridgeObjectRe|nonatomic_re|weak)",
    r"^_swift_release_dealloc", r"swift::RefCounts", r"^swift_deallocObject",
    r"^objc_(retain|release|autorelease|storeStrong|loadWeak|storeWeak|destructInstance)",
    r"^_?objc_msgSend", r"^lookUpImpOrForward", r"^cache_getImp", r"^object_getClass",
]
ISOLATION_CHECKS = [
    r"^_dispatch_assert_queue_fail", r"^dispatch_assert_queue",
    r"^swift_task_isCurrentExecutor", r"^_?swift_task_checkIsolated",
    r"^swift_task_reportUnexpectedExecutor",
]
SWIFT_REPORTING = [
    r"^_swift_runtime_on_report", r"^_swift_stdlib_reportFatalError", r"_assertionFailure",
    r"^swift::fatalError", r"^swift_reportError", r"^swift::swift_abortRetainUnowned",
    r"^swift_dynamicCastFailure", r"^swift::swift_dynamicCastFailure",
]
MALLOC_ERRORS = [
    r"___BUG_IN_CLIENT_OF_LIBMALLOC", r"^malloc_error_break", r"^malloc_zone_error",
    r"^_?xzm_.*(abort|corrupt|error)", r"^szone_error", r"^nanov2_guard_corruption",
    r"^malloc_report", r"^free_list_checksum_botch",
]
OBJC_THROW = [r"^objc_exception_throw", r"^objc_exception_rethrow", r"^-\[NSException raise\]"]
CXX_THROW = [r"^__cxa_throw", r"^__cxa_rethrow", r"^std::__terminate", r"^std::terminate",
             r"^__cxxabiv1::failed_throw"]
ASSERT = [r"^__assert_rtn", r"^__assert_fail"]
ABORT = [r"^abort$", r"^__abort", r"^abort_with_"]


# --- stack overflow -------------------------------------------------------------

_OUTLINED = re.compile(r"^outlined (?:init with copy|init with take|copy|assign with copy|assign with take|destroy) of (.+)$")


def _is_overflow(f):
    return is_chkstk(f.frame0) or f.fault_below_stack() is not None or f.sp_below_stack()


def _overflow_confidence(f):
    s = f.stack
    if is_chkstk(f.frame0) or f.sp_below_stack():
        return "high"
    if s is not None and s.percent is not None and s.percent >= 90:
        return "high"
    return "medium"


def _top_function(s):
    return s.by_function[0] if s and s.by_function else None


def _overflow_verdict(f, v):
    s = f.stack
    top = _top_function(s)
    if s.pattern == "infinite-recursion":
        cycle = " -> ".join(s.cycle)
        return "Stack overflow: infinite recursion in %s (%d repetitions)" % (cycle, s.cycle_reps)
    if s.pattern == "large-frames" and top:
        per_call = top.size // max(1, top.count)
        if top.count > 1:
            return "Stack overflow: deep chain of large frames (%s uses %s per call, x%d)" % (
                top.name, fmt_size(per_call), top.count)
        return "Stack overflow: deep chain of large frames (%s alone uses %s)" % (top.name, fmt_size(top.size))
    if s.pattern == "recursion":
        return "Stack overflow: deep recursion in %s (%d levels)" % (" -> ".join(s.cycle), s.cycle_reps)
    if s.chkstk and s.chkstk.requested:
        full = " on a %.0f%% full stack" % s.percent if s.percent is not None else ""
        return "Stack overflow: %s needed a %s frame%s (%s left)" % (
            s.chkstk.caller.name if s.chkstk.caller else "a function",
            fmt_size(s.chkstk.requested), full, fmt_size(s.chkstk.available))
    return "Stack overflow: the call chain is too deep for this thread's stack"


def _overflow_usage(f, v):
    s = f.stack
    if s.size:
        return "Stack: %s%s used of %s (%.1f%%) across %d frames on %s" % (
            "~" if s.approximate else "", fmt_size(s.used), fmt_size(s.size), s.percent,
            s.total_frames, f.ctx.thread.label)
    return "Stack: %s used across %d frames" % (fmt_size(s.used), s.total_frames)


def _overflow_sp(f, v):
    s = f.stack
    if s.sp_below_base:
        return "Frame 0's sp is already %s below the stack's base" % fmt_size(s.sp_below_base)
    return None


def _overflow_chkstk(f, v):
    c = f.stack.chkstk
    if c is None:
        return None
    caller = F.frame_label(c.caller) if c.caller else "the caller"
    if c.requested:
        return ("Frame 0 is ___chkstk_darwin, the stack probe for big frames: %s asked for %s (%d bytes, from %s) "
                "but only %s was left" % (caller, fmt_size(c.requested), c.requested, c.source, fmt_size(c.available)))
    return ("Frame 0 is ___chkstk_darwin, the stack probe for big frames: %s asked for more than the %s that was left"
            % (caller, fmt_size(c.available)))


def _overflow_pattern(f, v):
    s = f.stack
    if s.pattern in ("infinite-recursion", "recursion"):
        return "%s repeats %d times, %s per repetition" % (" -> ".join(s.cycle), s.cycle_reps, fmt_size(s.cycle_frame_size))
    top = _top_function(s)
    if top:
        return "Biggest consumer: %s x%d = %s (%s per call)" % (
            top.name, top.count, fmt_size(top.size), fmt_size(top.size // max(1, top.count)))
    return None


def _copied_type(f):
    c = f.stack.chkstk if f.stack else None
    if c and c.caller:
        m = _OUTLINED.match(c.caller.display or "") or _OUTLINED.match(c.caller.function or "")
        if m:
            return m.group(1)
    return None


def _overflow_copy_note(f, v):
    t = _copied_type(f)
    if not t:
        return None
    return ("'%s' is a compiler-generated helper that copies a value of type %s. A frame that big means the "
            "type itself is several KB: an enum is as large as its largest payload, and every copy reserves "
            "stack space" % (f.stack.chkstk.caller.name, t))


def _overflow_kind_note(f, v):
    s = f.stack
    if s.pattern == "infinite-recursion":
        return ("Look for a missing base case, a computed property or getter that reads itself, or an override "
                "calling itself instead of super")
    if s.pattern in ("large-frames",) or (s.chkstk and s.chkstk.requested and s.chkstk.requested >= 8192):
        return ("Large Swift frames come from big value types (structs/enums with many stored properties or large "
                "payloads) being copied or kept in locals. Box large payloads (an `indirect` enum case or a final "
                "class wrapper) so each copy is one pointer")
    return None


def _overflow_thread_note(f, v):
    if f.ctx.platform.startswith("ios") or not f.ctx.thread.is_main:
        return ("Default stacks: iOS main thread ~1 MB, secondary threads 512 KB, macOS main thread 8 MB. "
                "The simulator may use macOS's limits, so overflows can show up only on device")
    return None


def _overflow_type_step(f, v):
    t = _copied_type(f)
    if t:
        return "Check the copied type's size: `expression -l swift -- MemoryLayout<%s>.size`" % t
    return None


def _overflow_recursion_step(f, v):
    if f.stack.pattern in ("infinite-recursion", "recursion") and f.user_frame:
        return "Run `bt 30` to see the repeating cycle, then `frame select %d` to inspect why it doesn't stop" % f.user_frame.index
    return None


# --- bad access helpers -------------------------------------------------------------

def _nil_verdict(f, v):
    offset = f.null_offset()
    if offset is None:
        return "Bad pointer: %s is inside __PAGEZERO, so it is not a real pointer (a truncated 32-bit pointer, or an integer used as a pointer)" % v["fault"]
    if offset == 0:
        return "Nil/NULL pointer dereference"
    if offset > 0:
        return "Nil/NULL pointer dereference: accessed the field at offset %s of a nil pointer" % v["offset"]
    return "Nil/NULL pointer dereference: accessed %s bytes before a nil pointer (an object header or metadata read)" % v["offset"]


def _nil_confidence(f):
    offset = f.null_offset()
    return "high" if offset is not None and -0x1000 < offset < 0x1000 else "medium"


def _refcount_verdict(f, v):
    frame = f.find_frame(REFCOUNT_RUNTIME, 3)
    name = frame.name if frame else v["frame0_name"]
    if re.match(r"^_?objc_msgSend", name):
        return "Message sent to a deallocated or invalid Objective-C object (crashed in %s)" % name
    return "Use-after-free or over-release: %s touched an object that is no longer valid" % name


def _readonly_kind(f):
    r = f.ctx.fault_region
    section = (r.section if r else "") or ""
    if "__cstring" in section or "__ustring" in section:
        return "a string literal"
    if r is not None and r.executable:
        return "code"
    if "CONST" in section or "__const" in section or section.startswith("__TEXT"):
        return "constant data"
    return "read-only memory"


def _readonly_where(f):
    r = f.ctx.fault_region
    if r and r.section and r.image:
        return " (%s of %s)" % (r.section, r.image)
    if r and r.image:
        return " (in %s)" % r.image
    return ""


def _badfn_where(f, v):
    r = f.ctx.pc_region
    if r is not None and (r.readable or r.writable) and not r.executable:
        return "mapped but not executable (data, not code)"
    return "not mapped" if f.ctx.stop.exc_code == 1 else "not executable code"


def _caller_below(f):
    """First non-helper frame below the user frame: who invoked it."""
    u = f.user_frame
    if u is None:
        return None
    for frame in f.frames:
        if frame.index > u.index and not F.is_helper(frame):
            return frame
    return None


# --- Swift runtime failures -------------------------------------------------------------

SWIFT_MESSAGES = [
    # (pattern, verdict, note)
    (r"Unexpectedly found nil while implicitly unwrapping",
     "Implicitly unwrapped Optional was nil",
     "A `Type!` property was read while nil: often an @IBOutlet that isn't connected, or one used before the view loaded"),
    (r"Unexpectedly found nil while unwrapping",
     "Force unwrap of nil: `!` on an Optional that was nil",
     "Use `if let` / `guard let`, `?? default`, or make the failure explicit with a precondition message"),
    (r"Index out of range|index out of bounds",
     "Index out of range",
     "Check the index against `indices` or use `first` / `last`. A common cause is an index computed from a different "
     "or since-changed collection, e.g. a data source that changed under a table or list"),
    (r"[Aa]rithmetic overflow",
     "Integer overflow",
     "Swift integers trap on overflow. Use a wider type, the wrapping operators `&+ &- &*`, or `addingReportingOverflow`"),
    (r"Division by zero",
     "Integer division by zero",
     "Check the divisor before dividing"),
    (r"Division results in an overflow",
     "Integer division overflow (Int.min / -1)",
     "The result doesn't fit in the type"),
    (r"Range requires lowerBound <= upperBound",
     "Invalid range: lower bound greater than upper bound",
     "`a...b` and `a..<b` trap when a > b, e.g. `0..<count - 1` with an empty collection"),
    (r"unowned reference",
     "Accessed an `unowned` reference after its object was deallocated",
     "Use `weak` instead, or make sure the object outlives everything holding an unowned reference to it"),
    (r"Simultaneous accesses|exclusive access|access conflict",
     "Exclusivity violation: overlapping accesses to the same variable",
     "Two accesses to one variable overlap and one is a modification, e.g. passing `&x` inout while the callee also "
     "reads x, or mutating a property while it is being modified"),
    (r"Duplicate (keys|elements)",
     "Duplicate keys when building a Dictionary or Set",
     "Dictionary(uniqueKeysWithValues:) traps on duplicates; use Dictionary(_:uniquingKeysWith:)"),
    (r"Not enough bits to represent|Negative value is not representable|either infinite or NaN|cannot be converted",
     "Numeric conversion failed: the value doesn't fit the target type",
     "Use `Int(exactly:)`, `Int(clamping:)` or `Int(truncatingIfNeeded:)` instead of `Int(x)`"),
    (r"Can't remove (first|last) element from an empty",
     "removeFirst() / removeLast() on an empty collection",
     "Use popFirst() / popLast(), which return nil instead of trapping"),
    (r"Could not cast value of type",
     "Forced cast failed (`as!`)",
     "Use `as?` and handle the failure; the message names both types"),
    (r"Incorrect actor executor assumption",
     "assumeIsolated / preconditionIsolated was called off the expected actor",
     "The code assumed it was on an actor (usually the main actor) but was running elsewhere"),
    (r"init\(coder:\) has not been implemented",
     "init(coder:) was called, but it is a fatalError() stub",
     "This view or view controller is being loaded from a storyboard or nib"),
    (r"Use of unimplemented initializer",
     "An Objective-C superclass called an initializer your Swift subclass doesn't implement",
     "Override that initializer, or stop calling it"),
]


def _swift_message(f):
    stop = f.stop
    if stop.instrumentation_message:
        return stop.instrumentation_message
    name = f.frame0.display or f.frame0.function or ""
    if name.startswith("Swift runtime failure: "):
        return name[len("Swift runtime failure: "):]
    if stop.description.startswith(("Fatal error", "Precondition failed", "Assertion failed")):
        return stop.description
    return ""


def _strip_prefix(message):
    return re.sub(r"^(Fatal error|Precondition failed|Assertion failed): ", "", message)


def _swift_entry(f):
    message = _swift_message(f)
    for pattern, verdict, note in SWIFT_MESSAGES:
        if re.search(pattern, message):
            return verdict, note
    return None, None


def _is_swift_failure(f):
    stop = f.stop
    return (stop.instrumentation == "SwiftRuntimeReporting"
            or (f.frame0.display or "").startswith("Swift runtime failure:")
            or (f.frame0.function or "").startswith("Swift runtime failure:")
            or stop.description.startswith(("Fatal error:", "Precondition failed", "Assertion failed"))
            or bool(_swift_message(f) and f.top_match(6, SWIFT_REPORTING)))


def _swift_verdict(f, v):
    verdict, _ = _swift_entry(f)
    message = _swift_message(f)
    if verdict:
        return "Swift runtime trap: %s" % verdict
    kind = "fatalError / precondition"
    if message.startswith("Precondition failed"):
        kind = "precondition()"
    elif message.startswith("Assertion failed"):
        kind = "assert()"
    elif message.startswith("Fatal error"):
        kind = "fatalError()"
    return "Swift %s stopped the program: \"%s\"" % (kind, _strip_prefix(message))


def _swift_note(f, v):
    _, note = _swift_entry(f)
    return note


def _inspect_step(f, v):
    if f.user_frame:
        return "Run `frame select %d` then `frame variable` to inspect the values in your code" % f.user_frame.index
    return Steps.BT


# --- libdispatch / libplatform client bugs -------------------------------------------------

CLIENT_BUGS = [
    (r"__DISPATCH_WAIT_FOR_QUEUE__",
     "dispatch_sync onto the queue that is already running this code (deadlock)",
     "Calling DispatchQueue.sync on the current queue (often .main from the main thread) can never finish"),
    (r"dispatch_group_leave",
     "Unbalanced DispatchGroup.leave()",
     "leave() was called more times than enter(), e.g. a completion handler that runs twice"),
    (r"_os_unfair_lock_recursive_abort|os_unfair_lock_lock.*recursive",
     "os_unfair_lock locked recursively on the same thread",
     "The same thread tried to take a lock it already holds (OSAllocatedUnfairLock / os_unfair_lock are not recursive)"),
    (r"_os_unfair_lock_unowned_abort",
     "os_unfair_lock unlocked from a thread that doesn't own it",
     "Locks must be unlocked on the thread that locked them"),
    (r"_dispatch_semaphore_dispose",
     "DispatchSemaphore deallocated while still in use",
     "A semaphore was released with fewer signal() calls than its initial value"),
]


def _client_bug(f):
    for pattern, verdict, note in CLIENT_BUGS:
        if f.top_match(6, [pattern]):
            return verdict, note
    return None, None


# --- exceptions ---------------------------------------------------------------------------

NSEXCEPTION_HINTS = [
    (r"unrecognized selector",
     "A message went to an object of the wrong type: often a deallocated object whose memory was reused "
     "(enable Zombie Objects), or a wrong cast or bridging"),
    (r"NSRangeException|beyond bounds|out of bounds",
     "An index or range was outside an NSArray / NSString / NSData: often a Swift index used on a bridged "
     "collection, or an NSRange computed from a different string"),
    (r"NSUnknownKeyException|setValue:forUndefinedKey",
     "A storyboard / xib outlet or KVC key doesn't exist on the class (a stale outlet connection)"),
    (r"mutated while being enumerated",
     "A collection was changed while it was being iterated"),
    (r"NSInternalInconsistencyException",
     "An API's internal assertion failed: e.g. table/collection view updates that don't match the data source, "
     "or UI work on a background thread"),
    (r"attempt to insert nil|nil object",
     "nil was inserted into an Objective-C collection"),
]


def _exception_frame(f):
    exc = f.ctx.exception
    if exc and exc.backtrace:
        user = F.first_user_frame(exc.backtrace)
        if user:
            return user
    return f.user_frame


def _objc_verdict(f, v):
    exc = f.ctx.exception
    if exc and (exc.name or exc.reason):
        return "Uncaught Objective-C exception %s: %s" % (exc.name or "(unnamed)", exc.reason or "(no reason)")
    return "Uncaught Objective-C exception (its name and reason weren't readable; see the console above)"


def _objc_throw_site(f, v):
    exc = f.ctx.exception
    if exc and exc.backtrace:
        site = F.first_user_frame(exc.backtrace)
        if site:
            return "Thrown from %s" % F.frame_label(site)
    return None


def _objc_hint(f, v):
    exc = f.ctx.exception
    text = "%s %s" % (exc.name, exc.reason) if exc else ""
    for pattern, hint in NSEXCEPTION_HINTS:
        if re.search(pattern, text):
            return hint
    return None


def _abort_caller(f):
    for i, frame in enumerate(f.frames):
        if F.matches_any(frame, ABORT):
            for nxt in f.frames[i + 1:]:
                if not F.matches_any(nxt, ABORT):
                    return nxt
    return None


def _abort_verdict(f, v):
    caller = _abort_caller(f)
    if caller is not None:
        return "Deliberate abort(), called from %s" % (caller.name or "0x%x" % caller.pc)
    return "The program aborted (SIGABRT)"


def _malloc_verdict(f, v):
    if f.top_match(12, [r"POINTER_BEING_FREED_WAS_NOT_ALLOCATED"]):
        return "Freed a pointer that malloc doesn't own: a double free, or free() of a stack, interior or garbage pointer"
    return "Heap corruption detected by malloc"


def _exc_explanation(f, v):
    t = f.stop.exc_type
    if t in EXC_EXPLANATIONS:
        return "%s means %s" % (EXC_NAMES.get(t, t), EXC_EXPLANATIONS[t])
    s = f.stop.signal
    if s in SIGNAL_EXPLANATIONS:
        return "%s: %s" % (v["signal"], SIGNAL_EXPLANATIONS[s])
    return None


# --- the table ------------------------------------------------------------------------------

RULES = [
    Rule(
        id="not-a-crash",
        category="not-a-crash",
        when=lambda f: True,
        verdict="Not a crash: {description}",
        confidence="high",
        next_steps=["`why stack` works at any stop and shows how much stack this thread uses"],
    ),

    # ---- EXC_BAD_ACCESS / SIGSEGV / SIGBUS --------------------------------------------------
    Rule(
        id="stack-overflow",
        category="bad_access",
        when=_is_overflow,
        verdict=_overflow_verdict,
        confidence=_overflow_confidence,
        evidence=[_overflow_usage, _overflow_sp, _overflow_chkstk, _overflow_pattern],
        notes=[_overflow_copy_note, _overflow_kind_note, _overflow_thread_note],
        next_steps=[_overflow_type_step, _overflow_recursion_step, Steps.WHY_STACK],
        stack=True,
    ),
    Rule(
        id="malloc-error",
        category="any",
        when=lambda f: f.category in ("abort", "trap", "bad_access") and f.top_match(12, MALLOC_ERRORS),
        verdict=_malloc_verdict,
        confidence="high",
        notes=["The console usually shows a line like 'malloc: *** error for object 0x...: pointer being freed was not allocated'"],
        next_steps=[Steps.ASAN, Steps.MSL, Steps.SCRIBBLE],
    ),
    Rule(
        id="refcount-runtime",
        category="bad_access",
        when=lambda f: f.top_match(3, REFCOUNT_RUNTIME),
        verdict=_refcount_verdict,
        confidence="high",
        evidence=["The reference-counting / message-dispatch runtime reads an object's header first, so the object "
                  "pointer it was given was stale or garbage"],
        notes=["In Swift this usually means Unmanaged, unowned(unsafe) or an unsafe pointer kept an object past its "
               "lifetime, a manual over-release, or a data race on a reference (two threads assigning the same var)"],
        next_steps=[Steps.ZOMBIES, Steps.ASAN, Steps.MSL, Steps.TSAN],
    ),
    Rule(
        id="bad-function-pointer",
        category="bad_access",
        when=lambda f: f.fault_is_pc() or (f.ctx.pc_region is not None and f.ctx.pc_region.mapped
                                           and not f.ctx.pc_region.executable and f.fault == f.pc),
        verdict=lambda f, v: "Called a garbage function pointer or closure: jumped to %s, which is %s" % (v["fault"], _badfn_where(f, v)),
        confidence="high",
        evidence=["pc == fault address: the CPU faulted while fetching the instruction itself"],
        notes=["Typical causes: a function pointer or @convention(c) closure built from a bad integer (unsafeBitCast), "
               "calling a block or closure whose context was freed, or memory corruption overwriting a function pointer"],
        next_steps=[lambda f, v: ("Run `frame select %d` and `disassemble -f` to find the indirect call (blr/call) and "
                                  "the register that held %s" % (f.user_frame.index, v["fault"])) if f.user_frame else None,
                    Steps.ASAN, Steps.MSL],
    ),
    Rule(
        id="malloc-scribble",
        category="bad_access",
        when=lambda f: f.scribble() is not None,
        verdict=lambda f, v: ("Read a pointer from freed memory: %s is Malloc Scribble's 0x55 fill" % v["fault"]
                              if f.scribble() == "freed" else
                              "Used uninitialized heap memory: %s is Malloc Scribble's 0xAA fill" % v["fault"]),
        confidence="high",
        notes=["These fill patterns appear only when Malloc Scribble is on. On recent OS versions freed small blocks "
               "are zeroed instead, so a use-after-free can also look like a nil dereference"],
        next_steps=[Steps.ASAN, Steps.MSL],
    ),
    Rule(
        id="non-canonical",
        category="bad_access",
        when=lambda f: f.noncanonical(),
        verdict=lambda f, v: ("Pointer authentication failure: %s is a pointer whose signature didn't check out" % v["fault"]
                              if "pointer authentication" in f.stop.description.lower() else
                              "Corrupted pointer: %s is not a valid address (bits above the address range are set)" % v["fault"]),
        confidence=lambda f: "high" if "pointer authentication" in f.stop.description.lower() else "medium",
        notes=[lambda f, v: ("On arm64e a corrupted signed pointer (return address, function pointer, vtable or isa) "
                             "also looks like this" if f.ctx.arch == "arm64e" else
                             "This process isn't arm64e, so it isn't a pointer authentication failure: the pointer "
                             "value itself is garbage (freed memory, an uninitialized variable, or a buffer overflow "
                             "overwriting it)")],
        next_steps=["Run `register read` to see which register holds the bad value, and `disassemble -p` to see the "
                    "instruction that used it", Steps.ASAN, Steps.SCRIBBLE],
    ),
    Rule(
        id="nil-deref",
        category="bad_access",
        when=lambda f: f.in_pagezero() or f.null_offset() is not None,
        verdict=_nil_verdict,
        confidence=_nil_confidence,
        notes=["Safe Swift can't do this (Optionals trap with a message instead). Look for Objective-C or C code, "
               "Unmanaged, unowned(unsafe), Unsafe*Pointer, or an Objective-C API that returned nil despite being "
               "declared nonnull",
               "Recent allocators zero small freed blocks, so a pointer loaded from a freed object is nil too: if the "
               "object holding this pointer may already be gone, suspect a use-after-free"],
        next_steps=[_inspect_step, Steps.ASAN, Steps.ZOMBIES],
    ),
    Rule(
        id="write-readonly",
        category="bad_access",
        when=lambda f: (f.code == 2 and f.ctx.fault_region is not None and f.ctx.fault_region.mapped
                        and f.ctx.fault_region.readable and not f.ctx.fault_region.writable and not f.fault_is_pc()),
        verdict=lambda f, v: "Wrote to read-only memory: %s is %s%s" % (v["fault"], _readonly_kind(f), _readonly_where(f)),
        confidence="high",
        evidence=["code=2 on readable memory: the access was allowed to read but not to write"],
        notes=["In Swift this is usually UnsafeMutablePointer(mutating:) on a StaticString or string literal, or writing "
               "through a pointer from withUnsafeBytes"],
        next_steps=["Copy the data into memory you own before writing (a var Array, Data, or strdup)", Steps.ASAN],
    ),
    Rule(
        id="heap-address",
        category="bad_access",
        when=lambda f: f.ctx.fault_region is not None and f.ctx.fault_region.is_heap,
        verdict="Bad heap access: {fault} is in malloc memory that can't be accessed this way (likely freed)",
        confidence="medium",
        next_steps=[Steps.ASAN, Steps.MSL, Steps.ZOMBIES],
    ),
    Rule(
        id="bad-access-unclassified",
        category="bad_access",
        when=lambda f: True,
        verdict="Bad memory access at {fault} (unclassified)",
        confidence="low",
        next_steps=[lambda f, v: "Run `memory region %s` and `image lookup -a %s`" % (v["fault"], v["fault"]),
                    Steps.ASAN, Steps.SCRIBBLE],
    ),

    # ---- EXC_BREAKPOINT / EXC_BAD_INSTRUCTION / Swift runtime reporting ------------------------
    Rule(
        id="actor-isolation",
        category="trap",
        when=lambda f: f.top_match(8, ISOLATION_CHECKS),
        verdict="Swift concurrency isolation violation: {user_name} is isolated to the main actor but ran on {queue}",
        confidence="high",
        vars=lambda f: {
            "caller": F.frame_label(_caller_below(f)) if _caller_below(f) else "an unknown caller",
            # the check closest to the user's code is the one it called on entry
            "check": [fr for fr in f.frames[:8] if F.matches_any(fr, ISOLATION_CHECKS)][-1].name,
        },
        evidence=["The Swift runtime checked the executor on entry ({check}) and it wasn't the expected one",
                  "It was invoked by {caller}"],
        notes=[lambda f, v: ("This closure was inferred @MainActor because it was written in a @MainActor context (a "
                             "@MainActor type, a View, or a @MainActor function), but the API that called it delivers "
                             "its callback on a background queue without declaring it @Sendable"
                             if f.user_frame and "closure" in (f.user_frame.name or "") else
                             "Code isolated to the main actor was called from a background queue by code the compiler "
                             "couldn't check (Objective-C, C, or a module without strict concurrency)")],
        next_steps=["Mark the closure `@Sendable` (it then can't touch main-actor state directly) and hop back with "
                    "`Task { @MainActor in ... }` or `DispatchQueue.main.async`",
                    "If you own the API, declare the callback `@Sendable` (NS_SWIFT_SENDABLE in Objective-C); if not, "
                    "use `@preconcurrency import` for its module",
                    Steps.STRICT_CONCURRENCY],
    ),
    Rule(
        id="swift-runtime-failure",
        category="trap",
        when=_is_swift_failure,
        verdict=_swift_verdict,
        confidence="high",
        evidence=[lambda f, v: "Runtime message: \"%s\"" % _swift_message(f) if _swift_message(f) else None],
        notes=[_swift_note],
        next_steps=[_inspect_step, Steps.BT],
    ),
    Rule(
        id="client-bug",
        category="any",
        when=lambda f: f.category in ("trap", "abort", "bad_access") and _client_bug(f)[0] is not None,
        verdict=lambda f, v: "API misuse: %s" % _client_bug(f)[0],
        confidence="high",
        notes=[lambda f, v: _client_bug(f)[1]],
        next_steps=[_inspect_step, Steps.BT],
    ),
    Rule(
        id="swift-trap-unknown",
        category="trap",
        when=lambda f: f.user_frame is not None and f.user_frame.index <= 1 or f.top_match(6, SWIFT_REPORTING),
        verdict="Trap in {user_name} with no message: most likely a Swift runtime check (force unwrap, index, "
                "overflow, precondition) in optimized code",
        confidence="medium",
        notes=["Optimized builds without debug info drop the trap's reason. With debug info, lldb shows it as a "
               "'Swift runtime failure: ...' frame"],
        next_steps=["Build this target with debug info, or run the Debug configuration, to see the reason",
                    "Run `disassemble -p` to see the trapping instruction", _inspect_step],
    ),
    Rule(
        id="trap-unclassified",
        category="trap",
        when=lambda f: True,
        verdict="Trap instruction in {frame0_name} (unclassified)",
        confidence="low",
        evidence=[_exc_explanation],
        notes=["System libraries trap deliberately on misuse ('BUG IN CLIENT OF ...'); the console usually has the message"],
        next_steps=[Steps.BT, _inspect_step],
    ),

    # ---- SIGABRT / EXC_CRASH ---------------------------------------------------------------
    Rule(
        id="objc-exception",
        category="abort",
        when=lambda f: (f.ctx.exception is not None and f.ctx.exception.language == "objc") or f.top_match(None, OBJC_THROW),
        verdict=_objc_verdict,
        confidence="high",
        user_frame=_exception_frame,
        evidence=[_objc_throw_site],
        notes=[_objc_hint],
        next_steps=[Steps.EXCEPTION_BP, Steps.ZOMBIES],
    ),
    Rule(
        id="cxx-exception",
        category="abort",
        when=lambda f: (f.ctx.exception is not None and f.ctx.exception.language == "c++") or f.top_match(None, CXX_THROW),
        verdict=lambda f, v: ("Uncaught C++ exception %s: %s" % (f.ctx.exception.name, f.ctx.exception.reason)
                              if f.ctx.exception else "Uncaught C++ exception: std::terminate() was called"),
        confidence="medium",
        user_frame=_exception_frame,
        next_steps=[Steps.EXCEPTION_BP + " (include C++ exceptions)", Steps.BT],
    ),
    Rule(
        id="assert-failure",
        category="abort",
        when=lambda f: f.top_match(8, ASSERT),
        verdict="C assert() failed in {user_name}",
        confidence="medium",
        notes=["The console has the failed expression: 'Assertion failed: (expr), function f, file x, line n.'"],
        next_steps=[_inspect_step],
    ),
    Rule(
        id="abort-deliberate",
        category="abort",
        when=lambda f: True,
        verdict=_abort_verdict,
        confidence="medium",
        notes=["Code called abort() on purpose, usually right after printing why: look in the console just above"],
        next_steps=[Steps.EXCEPTION_BP, _inspect_step, Steps.BT],
    ),

    # ---- everything else -----------------------------------------------------------------
    Rule(
        id="arithmetic",
        category="arithmetic",
        when=lambda f: True,
        verdict="Arithmetic exception in {frame0_name}",
        confidence="medium",
        notes=["On arm64, integer division by zero doesn't trap in C; this usually comes from x86_64 code or "
               "enabled floating-point exceptions. Swift traps with its own message instead"],
        next_steps=[_inspect_step],
    ),
    Rule(
        id="resource",
        category="resource",
        when=lambda f: True,
        verdict="{exc}: resource limit or guard violation",
        confidence="medium",
        evidence=[_exc_explanation],
        next_steps=[Steps.BT_ALL],
    ),
    Rule(
        id="unclassified",
        category="any",
        when=lambda f: True,
        verdict="Unclassified stop: {description}",
        confidence="low",
        evidence=[_exc_explanation],
        next_steps=[Steps.BT, Steps.BT_ALL],
    ),
]
