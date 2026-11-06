"""`why auto on|off`: a scripted stop hook that runs the diagnosis when the
process crashes, and stays quiet on breakpoints, steps and other stops.

Added before any target exists (from ~/.lldbinit), the hook lands in lldb's
dummy target and is copied into every target created afterwards, which is
how Xcode creates them.
"""

import re

import lldb

from ..core import diagnose, render_diagnosis
from .gather import gather, stop_reason_name

CRASH_SIGNALS = (4, 5, 6, 8, 10, 11)   # SIGILL SIGTRAP SIGABRT SIGFPE SIGBUS SIGSEGV
HOOK_CLASS = "lldb_adapter.stophook.AutoHook"


def is_crash_stop(thread):
    reason = stop_reason_name(thread)
    if reason == "exception":
        return True
    if reason == "signal":
        return thread.GetStopReasonDataCount() > 0 and thread.GetStopReasonDataAtIndex(0) in CRASH_SIGNALS
    if reason == "instrumentation":
        stream = lldb.SBStream()
        thread.GetStopReasonExtendedInfoAsJSON(stream)
        return '"is_fatal": true' in (stream.GetData() or "").replace("\n", " ")
    return False


class AutoHook:
    def __init__(self, target, extra_args, internal_dict):
        self.target = target

    def handle_stop(self, exe_ctx, stream):
        try:
            thread = exe_ctx.GetThread()
            if not thread.IsValid() or not is_crash_stop(thread):
                return True
            from .commands import use_color
            debugger = self.target.GetDebugger()
            text = render_diagnosis(diagnose(gather(debugger, thread=thread)), color=use_color(debugger))
            stream.Print("\n" + text)
        except Exception as e:   # never break the user's debugging session
            stream.Print("why: auto analysis failed: %s\n" % e)
        return True   # keep the process stopped


def _hook_ids(debugger, package):
    result = lldb.SBCommandReturnObject()
    debugger.GetCommandInterpreter().HandleCommand("target stop-hook list", result)
    ids, current = [], None
    for line in (result.GetOutput() or "").splitlines():
        m = re.match(r"\s*Hook:\s*(\d+)", line)
        if m:
            current = m.group(1)
        elif current and ("Class:%s.%s" % (package, HOOK_CLASS)) in line.replace(" ", ""):
            ids.append(current)
    return ids


def command(debugger, value, package):
    ci = debugger.GetCommandInterpreter()
    ids = _hook_ids(debugger, package)
    if value == "on":
        if ids:
            return "why: auto analysis is already on"
        result = lldb.SBCommandReturnObject()
        ci.HandleCommand("target stop-hook add -P %s.%s" % (package, HOOK_CLASS), result)
        if not result.Succeeded():
            return "why: could not add the stop hook: %s" % result.GetError()
        where = "this target" if debugger.GetSelectedTarget().IsValid() else "every target created from now on"
        return "why: auto analysis on for %s: crashes are explained as soon as they happen" % where
    if value == "off":
        if not ids:
            return "why: auto analysis is already off"
        for hook_id in ids:
            ci.HandleCommand("target stop-hook delete %s" % hook_id, lldb.SBCommandReturnObject())
        return "why: auto analysis off"
    if value == "status":
        return "why: auto analysis is %s" % ("on" if ids else "off")
    return "usage: why auto on|off|status"
