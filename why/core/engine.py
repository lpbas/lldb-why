"""The rule engine: derives facts from a CrashContext and returns the
Diagnosis of the first rule (in table order) that matches."""

import re
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

from . import frames as F
from .model import Diagnosis, Frame
from .stack import analyze_stack
from .text import (
    EXC_BAD_ACCESS, EXC_BAD_INSTRUCTION, EXC_ARITHMETIC, EXC_BREAKPOINT, EXC_CRASH,
    EXC_RESOURCE, EXC_GUARD, SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGTRAP,
    bad_access_code_text, exc_name, fmt_size, signal_name, SIGNAL_EXPLANATIONS,
)

GUARD_WINDOW = 128 * 1024   # faults this far below a stack's base count as hitting its guard
NULL_WINDOW = 0x10000       # |offset| from NULL that still reads as "a field of a nil pointer"
DEFAULT_ADDRESS_MASK = 0xFFFF000000000000  # when the debugger could not tell us


def category_of(stop):
    t, s = stop.exc_type, stop.signal
    if stop.reason == "instrumentation":
        return "trap"
    if stop.reason in ("breakpoint", "trace", "plan", "watchpoint"):
        return "not-a-crash"
    if t == EXC_BAD_ACCESS or s in (SIGSEGV, SIGBUS):
        return "bad_access"
    if t in (EXC_BREAKPOINT, EXC_BAD_INSTRUCTION) or s in (SIGTRAP, SIGILL):
        return "trap"
    if s == SIGABRT or t == EXC_CRASH:
        return "abort"
    if t == EXC_ARITHMETIC or s == SIGFPE:
        return "arithmetic"
    if t in (EXC_RESOURCE, EXC_GUARD):
        return "resource"
    if stop.reason == "signal":
        return "not-a-crash" if s not in SIGNAL_EXPLANATIONS else "other"
    return "other"


class Facts:
    """Convenient, derived views of a CrashContext for rules to test."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.stop = ctx.stop
        self.frames = sorted(ctx.frames, key=lambda f: f.index)
        self.frame0 = self.frames[0] if self.frames else Frame()
        self.pc = self.frame0.pc
        self.fault = ctx.stop.fault_address
        self.code = ctx.stop.exc_code
        self.category = category_of(ctx.stop)
        self.user_frame = F.first_user_frame(self.frames)
        self._stack = None

    # -- stack -----------------------------------------------------------------
    @property
    def stack(self):
        if self._stack is None:
            self._stack = analyze_stack(self.ctx)
        return self._stack

    @property
    def stack_region(self):
        return self.ctx.stack_region

    def fault_below_stack(self):
        """Bytes between the fault and the stack's base, if the fault is in the guard window."""
        r = self.stack_region
        if r is None or self.fault is None:
            return None
        if r.base - GUARD_WINDOW <= self.fault < r.base:
            return r.base - self.fault
        return None

    def sp_below_stack(self):
        r = self.stack_region
        return r is not None and bool(self.frames) and self.frame0.sp < r.base

    # -- address shapes --------------------------------------------------------
    def null_offset(self):
        """Offset from NULL (negative for NULL minus something), or None."""
        a = self.fault
        if a is None:
            return None
        if a < NULL_WINDOW:
            return a
        if a >= (1 << 64) - NULL_WINDOW:
            return a - (1 << 64)
        return None

    def in_pagezero(self):
        return self.fault is not None and self.fault < self.ctx.pagezero_end

    def noncanonical(self):
        if self.fault is None:
            return False
        mask = self.ctx.address_mask or DEFAULT_ADDRESS_MASK
        return bool(self.fault & mask) and self.null_offset() is None

    def scribble(self):
        """'freed' for 0x5555..., 'uninitialized' for 0xaaaa..., else None."""
        if self.fault is None:
            return None
        high = self.fault >> 32
        if high == 0x55555555:
            return "freed"
        if high == 0xAAAAAAAA:
            return "uninitialized"
        return None

    def fault_is_pc(self):
        return self.fault is not None and self.fault == self.pc

    # -- frames ----------------------------------------------------------------
    def top_match(self, n, patterns):
        return self.find_frame(patterns, n) is not None

    def find_frame(self, patterns, n=None):
        for frame in self.frames[:n] if n else self.frames:
            if F.matches_any(frame, patterns):
                return frame
        return None

    # -- descriptions ----------------------------------------------------------
    def describe_address(self, address, region=None):
        ctx = self.ctx
        stack = ctx.stack_region
        if address is None:
            return "unknown address"
        if stack is not None and stack.contains(address):
            return "inside the stack of %s" % ctx.thread.label
        if stack is not None and stack.base - GUARD_WINDOW <= address < stack.base:
            return "%s below the stack of %s, in its guard page" % (fmt_size(stack.base - address), ctx.thread.label)
        if address < ctx.pagezero_end:
            return "inside __PAGEZERO (the first %s of the address space, never mapped)" % fmt_size(ctx.pagezero_end)
        if region is None:
            return "no memory region information"
        if not region.mapped and not (region.readable or region.writable or region.executable):
            return "unmapped memory"
        parts = ["mapped %s" % region.perms]
        if region.type:
            parts.append(region.type.replace(",", ", "))
        if region.section and region.image:
            parts.append("in %s of %s" % (region.section, region.image))
        elif region.image:
            parts.append("in %s" % region.image)
        return " ".join(parts) + " [0x%x-0x%x)" % (region.base, region.end)

    def variables(self):
        ctx, stop = self.ctx, self.stop
        offset = self.null_offset()
        exc = ctx.exception
        return {
            "fault": "0x%x" % self.fault if self.fault is not None else "?",
            "pc": "0x%x" % self.pc,
            "code": bad_access_code_text(self.code),
            "exc": exc_name(stop.exc_type) if stop.exc_type is not None else signal_name(stop.signal),
            "signal": signal_name(stop.signal) if stop.signal is not None else "",
            "description": stop.description,
            "message": stop.instrumentation_message or stop.description,
            "frame0": F.frame_label(self.frame0),
            "frame0_name": self.frame0.name or "0x%x" % self.pc,
            "user": F.frame_label(self.user_frame) if self.user_frame else "no frame in your code",
            "user_name": self.user_frame.name if self.user_frame else "your code",
            "thread": ctx.thread.label,
            "queue": ctx.thread.queue or "no queue",
            "fault_region": self.describe_address(self.fault, ctx.fault_region),
            "offset": ("%#x" % offset) if offset is not None and offset >= 0 else ("-%#x" % -offset if offset is not None else "?"),
            "exc_name": exc.name if exc else "",
            "exc_reason": exc.reason if exc else "",
        }


Template = Any  # str (formatted with Facts.variables() + Rule.vars) or callable(facts, vars) -> str | None


@dataclass
class Rule:
    """One crash signature. See CONTRIBUTING.md for how to add one.

    category:  which stops it applies to: bad_access | trap | abort | arithmetic |
               resource | other | not-a-crash | any
    when:      predicate over Facts
    verdict, evidence, notes, next_steps: templates; a callable returning None
               or "" drops the line.
    confidence: "high" | "medium" | "low", or a callable(facts) returning one.
    vars:      callable(facts) -> dict of extra template variables.
    user_frame: callable(facts) -> Frame, when the interesting frame is not the
               first user frame of the crashed thread (e.g. an exception's throw site).
    stack:     run the stack analyzer and include its summary.
    """

    id: str
    category: str
    when: Callable
    verdict: Template
    confidence: Any = "medium"
    evidence: List[Template] = field(default_factory=list)
    notes: List[Template] = field(default_factory=list)
    next_steps: List[Template] = field(default_factory=list)
    vars: Optional[Callable] = None
    user_frame: Optional[Callable] = None
    stack: bool = False


_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _render(template, facts, variables):
    """Fill `{name}` placeholders. Other braces (Swift code such as
    `Task { @MainActor in ... }`) are left alone. An unknown name raises
    KeyError so typos in rules fail the unit tests."""
    if template is None:
        return None
    if callable(template):
        return template(facts, variables)
    return _PLACEHOLDER.sub(lambda m: str(variables[m.group(1)]), template)


def common_evidence(facts):
    stop, ctx = facts.stop, facts.ctx
    lines = []
    if facts.category == "bad_access" and stop.exc_type == EXC_BAD_ACCESS:
        lines.append("%s %s at address 0x%x" % (exc_name(stop.exc_type), bad_access_code_text(stop.exc_code),
                                                 facts.fault or 0))
    elif stop.reason == "instrumentation":
        lines.append("Stopped by lldb's %s before the trap: %s" % (stop.instrumentation or "runtime check",
                                                                   stop.instrumentation_message or stop.description))
    elif stop.description:
        lines.append("Stop reason: %s" % stop.description)
    if facts.category == "bad_access" and facts.fault is not None:
        lines.append("Address 0x%x is %s" % (facts.fault, facts.describe_address(facts.fault, ctx.fault_region)))
    if facts.frames:
        lines.append("Crashed in %s" % F.frame_label(facts.frame0))
    return lines


def build(rule, facts):
    variables = facts.variables()
    if rule.vars:
        variables.update(rule.vars(facts) or {})

    def render_all(templates):
        out = []
        for t in templates:
            text = _render(t, facts, variables)
            if text:
                out.append(text)
        return out

    user_frame = rule.user_frame(facts) if rule.user_frame else facts.user_frame
    where = []
    if user_frame is not None:
        where.append("Your code: %s" % F.frame_label(user_frame))
        if not rule.user_frame:
            for helper in F.helpers_before(facts.frames, user_frame):
                where.append("Via compiler-generated %s" % F.frame_label(helper))
    else:
        where.append("No frame from your own code on this thread")

    confidence = rule.confidence(facts) if callable(rule.confidence) else rule.confidence
    return Diagnosis(
        rule_id=rule.id,
        verdict=_render(rule.verdict, facts, variables),
        confidence=confidence,
        evidence=common_evidence(facts) + render_all(rule.evidence),
        where=where,
        notes=render_all(rule.notes),
        next_steps=render_all(rule.next_steps),
        user_frame=user_frame,
        stack=facts.stack if rule.stack else None,
    )


def diagnose(ctx, rules=None):
    """Classify a CrashContext. Returns a Diagnosis (never None)."""
    if rules is None:
        from .rules import RULES as rules
    facts = Facts(ctx)
    for rule in rules:
        if rule.category not in ("any", facts.category):
            continue
        if rule.when(facts):
            return build(rule, facts)
    raise RuntimeError("no rule matched; the table must end with a catch-all rule")
