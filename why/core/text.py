"""Plain-English names for exception types, codes and signals, and the catalog
of next steps that rules can point to."""

EXC_BAD_ACCESS = 1
EXC_BAD_INSTRUCTION = 2
EXC_ARITHMETIC = 3
EXC_BREAKPOINT = 6
EXC_CRASH = 10
EXC_RESOURCE = 11
EXC_GUARD = 12

EXC_NAMES = {
    1: "EXC_BAD_ACCESS",
    2: "EXC_BAD_INSTRUCTION",
    3: "EXC_ARITHMETIC",
    4: "EXC_EMULATION",
    5: "EXC_SOFTWARE",
    6: "EXC_BREAKPOINT",
    7: "EXC_SYSCALL",
    8: "EXC_MACH_SYSCALL",
    9: "EXC_RPC_ALERT",
    10: "EXC_CRASH",
    11: "EXC_RESOURCE",
    12: "EXC_GUARD",
    13: "EXC_CORPSE_NOTIFY",
}

EXC_EXPLANATIONS = {
    1: "the program touched memory it may not access",
    2: "the CPU hit an illegal or undefined instruction (on x86_64 this is how Swift traps)",
    3: "an arithmetic error such as an integer division by zero",
    6: "a trap instruction ran: a Swift runtime check failed, or code called __builtin_trap()",
    10: "the process was terminated, usually by abort() or an uncaught exception",
    11: "the process exceeded a resource limit (CPU, memory, wakeups or file descriptors)",
    12: "the process violated a guarded resource, e.g. closed a file descriptor it does not own",
}

# EXC_BAD_ACCESS codes (kern_return_t values, plus arm64-specific ones)
BAD_ACCESS_CODES = {
    1: ("KERN_INVALID_ADDRESS", "nothing is mapped at that address"),
    2: ("KERN_PROTECTION_FAILURE", "memory is mapped there, but this kind of access is not allowed"),
    0x101: ("EXC_ARM_DA_ALIGN", "misaligned memory access"),
    0x102: ("EXC_ARM_DA_DEBUG", "hardware watchpoint or debug exception"),
}

SIGNAL_NAMES = {
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    8: "SIGFPE",
    9: "SIGKILL",
    10: "SIGBUS",
    11: "SIGSEGV",
    12: "SIGSYS",
    13: "SIGPIPE",
}

SIGILL, SIGTRAP, SIGABRT, SIGFPE, SIGBUS, SIGSEGV = 4, 5, 6, 8, 10, 11

SIGNAL_EXPLANATIONS = {
    4: "illegal instruction",
    5: "trap instruction",
    6: "the process called abort()",
    8: "arithmetic error",
    9: "the process was killed (by the system, the debugger or a watchdog)",
    10: "bus error: invalid memory access",
    11: "segmentation fault: invalid memory access",
    13: "wrote to a pipe or socket whose other end is closed",
}


def exc_name(exc_type):
    return EXC_NAMES.get(exc_type, "exception %s" % exc_type)


def signal_name(signo):
    return SIGNAL_NAMES.get(signo, "signal %s" % signo)


def bad_access_code_text(code):
    """'code=2 (KERN_PROTECTION_FAILURE: memory is mapped there, ...)'"""
    if code is None:
        return ""
    name, meaning = BAD_ACCESS_CODES.get(code, ("", ""))
    if not name:
        return "code=%#x" % code
    return "code=%d (%s: %s)" % (code, name, meaning)


def fmt_size(n):
    """Human-readable byte count: '48 B', '15.0 KB', '8.06 MB'."""
    if n is None:
        return "?"
    sign = "-" if n < 0 else ""
    n = abs(n)
    if n < 1024:
        return "%s%d B" % (sign, n)
    if n < 1024 * 1024:
        return "%s%.1f KB" % (sign, n / 1024.0)
    return "%s%.2f MB" % (sign, n / (1024.0 * 1024.0))


class Steps:
    """Next steps that rules refer to. Keep each one a single actionable line."""

    ASAN = ("Enable Address Sanitizer (Edit Scheme > Run > Diagnostics > Address Sanitizer) "
            "and reproduce: it stops at the bad access and shows where the memory was freed")
    ZOMBIES = ("Enable Zombie Objects (Edit Scheme > Run > Diagnostics) to catch messages "
               "sent to deallocated Objective-C objects")
    SCRIBBLE = ("Enable Malloc Scribble (Edit Scheme > Run > Diagnostics): freed memory is "
                "filled with 0x55 and new memory with 0xAA, so stale reads crash recognizably")
    MSL = ("Enable Malloc Stack Logging (Edit Scheme > Run > Diagnostics), then run "
           "`memory history <address>` in lldb to see who allocated and freed the memory")
    TSAN = ("Enable Thread Sanitizer (Edit Scheme > Run > Diagnostics) to find the data race "
            "or the wrong-queue call")
    EXCEPTION_BP = ("Add an Exception Breakpoint (Breakpoint navigator > + > Exception Breakpoint, "
                    "All exceptions) so the debugger stops where the exception is thrown")
    STRICT_CONCURRENCY = ("Turn on complete concurrency checking (SWIFT_STRICT_CONCURRENCY = complete) "
                          "to get compile-time warnings for the same problem")
    WHY_STACK = "Run `why stack` for the full stack usage report"
    BT = "Run `bt` to see the whole backtrace"
    BT_ALL = "Run `bt all` to see what the other threads were doing"


# Module names treated as SwiftUI for the stack summary.
SWIFTUI_MODULES = frozenset(["SwiftUI", "SwiftUICore", "AttributeGraph"])
