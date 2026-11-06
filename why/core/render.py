"""Text output. Plain text by default: Xcode's console doesn't render ANSI."""

import os

from . import frames as F
from .text import fmt_size

_BOLD, _RED, _YELLOW, _GREEN, _DIM, _RESET = "\033[1m", "\033[31m", "\033[33m", "\033[32m", "\033[2m", "\033[0m"
_CONFIDENCE_COLOR = {"high": _RED, "medium": _YELLOW, "low": _DIM}

PATTERN_TEXT = {
    "infinite-recursion": "infinite recursion",
    "recursion": "deep recursion",
    "large-frames": "deep chain of large frames",
    "deep-chain": "deep call chain",
    "normal": "nothing unusual",
}


class _Style:
    def __init__(self, color):
        self.color = color

    def __call__(self, text, *codes):
        if not self.color or not codes:
            return text
        return "".join(codes) + text + _RESET


def render_diagnosis(d, color=False):
    s = _Style(color)
    lines = [
        "%s %s  [confidence: %s]" % (s("why:", _BOLD), s(d.verdict, _BOLD),
                                     s(d.confidence, _CONFIDENCE_COLOR.get(d.confidence, ""))),
        "",
    ]
    _section(lines, s, "Evidence", d.evidence)
    _section(lines, s, "Where", d.where)
    if d.stack is not None:
        _section(lines, s, "Stack", stack_summary(d.stack))
    _section(lines, s, "Notes", d.notes)
    if d.next_steps:
        lines.append(s("Next steps", _BOLD))
        for i, step in enumerate(d.next_steps, 1):
            lines.append("  %d. %s" % (i, step))
    return "\n".join(lines).rstrip() + "\n"


def _section(lines, s, title, items):
    if not items:
        return
    lines.append(s(title, _BOLD))
    for item in items:
        lines.append("  - %s" % item)
    lines.append("")


def stack_summary(r, top=3):
    """A few lines for the crash verdict; `why stack` prints the full report."""
    out = []
    if r.largest:
        seen, parts = set(), []
        for fs in r.largest:
            name = fs.frame.name or "0x%x" % fs.frame.pc
            if name not in seen:
                seen.add(name)
                parts.append("%s %s" % (fmt_size(fs.size), name))
            if len(parts) == top:
                break
        out.append("Largest frames: " + ", ".join(parts))
    c, b = r.counts, r.category_bytes

    def part(key, label):
        return "%d %s (%s)" % (c.get(key, 0), label, fmt_size(b.get(key, 0)))

    parts = [part("user", "yours"), part("swiftui", "SwiftUI"), part("system", "system")]
    if c.get("unknown"):
        parts.append(part("unknown", "unknown"))
    out.append("Frames: " + ", ".join(parts))
    return out


def render_stack(r, color=False):
    s = _Style(color)
    lines = [s("Stack usage for %s" % r.thread_label, _BOLD)]
    if r.region is not None:
        lines.append("  Region    0x%x-0x%x (%s)" % (r.region.base, r.region.end, fmt_size(r.region.size)))
    else:
        lines.append("  Region    unknown (no mapped region contains this thread's stack pointers)")
    walked = "%d frames" % r.total_frames
    if r.total_frames > r.frames_walked:
        walked += " (%d walked)" % r.frames_walked
    if r.size:
        lines.append("  Used      %s%s of %s (%.1f%%) across %s" % (
            "~" if r.approximate else "", fmt_size(r.used), fmt_size(r.size), r.percent, walked))
    else:
        lines.append("  Used      %s across %s" % (fmt_size(r.used), walked))
    if r.region is not None:
        if r.sp_below_base:
            lines.append("  Frame 0   sp is %s below the stack's base (inside the guard page)" % fmt_size(r.sp_below_base))
        else:
            lines.append("  Frame 0   sp has %s left before the stack's base" % fmt_size(r.sp0 - r.region.base))
    c = r.chkstk
    if c is not None:
        caller = F.frame_label(c.caller) if c.caller else "the caller"
        if c.requested:
            lines.append("  chkstk    %s requested %s (%d bytes; %s); %s was left" % (
                caller, fmt_size(c.requested), c.requested, c.source, fmt_size(c.available)))
        else:
            lines.append("  chkstk    %s requested more than the %s that was left" % (caller, fmt_size(c.available)))
    pattern = PATTERN_TEXT.get(r.pattern, r.pattern)
    if r.cycle_reps:
        pattern += ": %s x%d (%s per repetition)" % (" -> ".join(r.cycle), r.cycle_reps, fmt_size(r.cycle_frame_size))
    lines.append("  Pattern   %s" % pattern)

    if r.largest:
        lines.append("")
        lines.append(s("  Largest frames", _BOLD))
        width = max(len(fmt_size(fs.size)) for fs in r.largest)
        for fs in r.largest:
            f = fs.frame
            where = ""
            if f.file and not f.file.startswith("<"):
                where = "  %s%s" % (os.path.basename(f.file), ":%d" % f.line if f.line else "")
            elif f.module:
                where = "  (%s)" % f.module
            lines.append("    %s  #%-5d %s%s" % (fmt_size(fs.size).rjust(width), f.index, f.name or "0x%x" % f.pc, where))
    if r.by_function:
        lines.append("")
        lines.append(s("  By function", _BOLD))
        width = max(len(fmt_size(t.size)) for t in r.by_function)
        for t in r.by_function:
            lines.append("    %s  %6d %s  %s" % (fmt_size(t.size).rjust(width), t.count,
                                                "call " if t.count == 1 else "calls", t.name))
    lines.append("")
    lines.append("  " + stack_summary(r)[-1])
    return "\n".join(lines) + "\n"
