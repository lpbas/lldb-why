"""Stack usage analysis: how much of the thread's stack is used, by which
frames, whether it looks like runaway recursion, and, when the crash happened
in ___chkstk_darwin, how big the frame being allocated was.

Verified on arm64 macOS 26 (see docs/FINDINGS.md):
  * The caller loads the frame size into x9, in bytes (`mov w9, #0x3bd0`), calls
    ___chkstk_darwin, then does `sub sp, sp, x9`-equivalent.
  * When the frame does not fit, ___chkstk_darwin deliberately reads
    stack_limit - 8, so the fault address says nothing about the frame size.
  * x9 is still intact on that path, but the page-probing loop decrements it, so
    the caller's prologue is the authoritative source and x9 the cross-check.
  * On x86_64 the size is passed in rax (from the ABI; not verified here).
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional

from . import frames as F
from .model import Frame, Region
from .text import SWIFTUI_MODULES

CHKSTK_NAMES = ("___chkstk_darwin", "__chkstk_darwin", "__chkstk_darwin_probe")
LARGE_FRAME = 4096          # frames at least this big count as "large"
INFINITE_REPS = 256         # a cycle repeated this often is treated as unbounded recursion
RECURSION_REPS = 16
MAX_CYCLE = 8               # longest recursion cycle we look for (a -> b -> ... -> a)


@dataclass
class FrameSize:
    frame: Frame
    size: int


@dataclass
class FunctionTotal:
    name: str
    count: int
    size: int


@dataclass
class ChkstkRequest:
    caller: Optional[Frame]
    requested: Optional[int]        # bytes the caller asked for, if known
    source: str                     # how `requested` was determined
    confirmed: bool                 # prologue and register agree
    available: Optional[int]        # bytes left between frame 0's sp and the stack limit


@dataclass
class StackReport:
    thread_label: str
    region: Optional[Region]
    used: int
    size: Optional[int]
    approximate: bool               # the frame walk was capped, `used` comes from the region end
    frames_walked: int
    total_frames: int
    sp0: int
    sp_below_base: int              # how far frame 0's sp is already below the stack's base
    largest: List[FrameSize] = field(default_factory=list)
    by_function: List[FunctionTotal] = field(default_factory=list)
    counts: dict = field(default_factory=dict)      # frames per category: user / swiftui / system / unknown
    category_bytes: dict = field(default_factory=dict)  # stack bytes per category
    pattern: str = "normal"         # infinite-recursion | recursion | large-frames | deep-chain | normal
    cycle: List[str] = field(default_factory=list)
    cycle_reps: int = 0
    cycle_frame_size: int = 0       # average bytes per repetition of the cycle
    large_bytes: int = 0            # bytes in frames >= LARGE_FRAME
    chkstk: Optional[ChkstkRequest] = None

    @property
    def percent(self):
        if not self.size:
            return None
        return 100.0 * self.used / self.size


def is_chkstk(frame):
    return frame is not None and (frame.function in CHKSTK_NAMES or frame.display in CHKSTK_NAMES)


# --- prologue parsing -------------------------------------------------------

_IMM = r"#?(-?0x[0-9a-fA-F]+|-?\d+)"
_ARM_MOV = re.compile(r"^[wx]9,\s*" + _IMM + r"(?:,\s*lsl\s*#?(\d+))?")
_X86_ATT = re.compile(r"^\$(0x[0-9a-fA-F]+|\d+),\s*%[er]ax$")
_X86_INTEL = re.compile(r"^[er]ax,\s*(0x[0-9a-fA-F]+|\d+)$")


def _operands(text):
    return text.split(";", 1)[0].strip()


def prologue_frame_size(instructions, arch):
    """The value of the chkstk size register (x9 on arm64, rax on x86_64) at
    the end of `instructions`, the caller's code from its entry up to the call.

    instructions: [[mnemonic, operands], ...]. Returns None if not found.
    """
    value = None
    if arch.startswith("arm64"):
        for mnemonic, operands in instructions:
            m = _ARM_MOV.match(_operands(operands))
            mnemonic = mnemonic.lower()
            if not m:
                # Any other write to x9/w9 invalidates what we know.
                if re.match(r"^[wx]9\b", _operands(operands)) and not mnemonic.startswith(("st", "cmp", "tst", "cb", "tb")):
                    value = None
                continue
            imm = int(m.group(1), 0)
            shift = int(m.group(2) or 0)
            if mnemonic in ("mov", "movz"):
                value = (imm << shift) & 0xFFFFFFFFFFFFFFFF
            elif mnemonic == "movk":
                lane = 0xFFFF << shift
                value = ((value or 0) & ~lane) | ((imm << shift) & lane)
            elif mnemonic == "orr":
                value = imm
    elif arch.startswith("x86"):
        for mnemonic, operands in instructions:
            if not mnemonic.lower().startswith("mov"):
                continue
            ops = _operands(operands)
            m = _X86_ATT.match(ops) or _X86_INTEL.match(ops)
            if m:
                value = int(m.group(1), 0)
    return value


def analyze_chkstk(ctx):
    frames = ctx.frames
    if not frames or not is_chkstk(frames[0]):
        return None
    caller = frames[1] if len(frames) > 1 else None
    sp0 = frames[0].sp
    fault = ctx.stop.fault_address
    limit = None
    if ctx.stack_region is not None:
        limit = ctx.stack_region.base
    elif fault is not None:
        limit = fault + 8
    available = sp0 - limit if limit is not None else None

    from_prologue = prologue_frame_size(ctx.caller_prologue, ctx.arch) if ctx.caller_prologue else None
    reg_name = "rax" if ctx.arch.startswith("x86") else "x9"
    from_register = ctx.registers.get(reg_name)
    # The probing loop decrements the register; a value smaller than what was
    # available cannot be the original request (it would have fit).
    if from_register is not None and available is not None and from_register <= available:
        from_register = None

    if from_prologue:
        requested = from_prologue
        confirmed = from_register == from_prologue
        source = "caller's prologue" + (", matches %s" % reg_name if confirmed else "")
    elif from_register:
        requested, confirmed, source = from_register, False, "%s register" % reg_name
    else:
        requested, confirmed = None, False
        source = "unknown; more than %d bytes" % available if available is not None else "unknown"
    return ChkstkRequest(caller=caller, requested=requested, source=source,
                         confirmed=confirmed, available=available)


# --- recursion detection ----------------------------------------------------

def _find_cycle(frames):
    """The shortest repeating cycle at the top of the stack that includes the
    user's own code (SwiftUI and other frameworks repeat their own frames in
    deep but legitimate view hierarchies; that is not recursion).

    Returns (cycle names, repetitions, start index) or ([], 0, 0).
    """
    names = [f.name for f in frames]
    n = len(names)
    best = ([], 0, 0)
    for start in range(min(4, n)):
        for period in range(1, MAX_CYCLE + 1):
            if start + 2 * period > n:
                break
            i = start
            while i + period < n and names[i] == names[i + period]:
                i += 1
            reps = (i - start) // period + 1
            if reps >= RECURSION_REPS and any(names[start:start + period]):
                if not any(classify_frame(f) in ("user", "unknown") and f.name
                           for f in frames[start:start + period]):
                    break
                if reps > best[1]:
                    best = (names[start:start + period], reps, start)
                break  # a longer period would only repeat the same cycle
        if best[1] >= INFINITE_REPS:
            break
    return best


def classify_frame(frame):
    if frame.module in SWIFTUI_MODULES:
        return "swiftui"
    if not frame.module:
        return "unknown"
    if F.is_system_module(frame):
        return "system"
    return "user"


def analyze_stack(ctx, top=10):
    frames = sorted(ctx.frames, key=lambda f: f.index)
    if not frames:
        return None
    region = ctx.stack_region
    sp0 = frames[0].sp
    approximate = ctx.frames_truncated or len(frames) == 1
    if approximate and region is not None:
        used = region.end - sp0
    else:
        used = frames[-1].sp - sp0
    size = region.size if region is not None else None
    sp_below_base = max(0, region.base - sp0) if region is not None else 0

    sizes = []
    for a, b in zip(frames, frames[1:]):
        delta = b.sp - a.sp
        if delta >= 0:
            sizes.append(FrameSize(a, delta))

    totals = {}
    large_bytes = 0
    for fs in sizes:
        name = fs.frame.name or "0x%x" % fs.frame.pc
        count, total = totals.get(name, (0, 0))
        totals[name] = (count + 1, total + fs.size)
        if fs.size >= LARGE_FRAME:
            large_bytes += fs.size
    by_function = sorted((FunctionTotal(k, c, s) for k, (c, s) in totals.items()),
                         key=lambda t: t.size, reverse=True)

    counts = {"user": 0, "swiftui": 0, "system": 0, "unknown": 0}
    category_bytes = dict.fromkeys(counts, 0)
    for frame in frames:
        counts[classify_frame(frame)] += 1
    for fs in sizes:
        category_bytes[classify_frame(fs.frame)] += fs.size

    cycle, reps, start = _find_cycle(frames)
    cycle_frame_size = 0
    if reps:
        span = frames[start:start + reps * len(cycle) + 1]
        if len(span) > 1:
            cycle_frame_size = (span[-1].sp - span[0].sp) // max(1, reps)

    report = StackReport(
        thread_label=ctx.thread.label,
        region=region,
        used=used,
        size=size,
        approximate=approximate,
        frames_walked=len(frames),
        total_frames=max(ctx.total_frames, len(frames)),
        sp0=sp0,
        sp_below_base=sp_below_base,
        largest=sorted(sizes, key=lambda s: s.size, reverse=True)[:top],
        by_function=by_function[:5],
        counts=counts,
        category_bytes=category_bytes,
        cycle=cycle,
        cycle_reps=reps,
        cycle_frame_size=cycle_frame_size,
        large_bytes=large_bytes,
        chkstk=analyze_chkstk(ctx),
    )
    report.pattern = _pattern(report)
    return report


def _pattern(report):
    percent = report.percent
    # At an ordinary stop with plenty of stack left, big frames or a long cycle
    # are worth listing but not worth a scary label.
    filling = percent is None or percent >= 50
    if report.cycle_reps >= INFINITE_REPS and filling:
        return "infinite-recursion"
    if report.used and report.large_bytes * 2 >= report.used and filling:
        return "large-frames"
    if report.cycle_reps >= RECURSION_REPS:
        return "recursion"
    if percent is not None and percent >= 90:
        return "deep-chain"
    return "normal"
