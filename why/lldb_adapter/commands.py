"""The `why` lldb command and its subcommands.

    why                  explain the current stop of the crashed (or selected) thread
    why stack            stack usage report for the selected thread (works at any stop)
    why auto on|off      run `why` automatically whenever the process crashes
    why auto status
    why dump-context     print the gathered data as JSON (add --expect for a test fixture)

`diagnose` is an alias for `why`.
"""

import argparse
import json
import os
import shlex
import sys
import traceback

import lldb

from .. import __version__
from ..core import analyze_stack, diagnose, render_diagnosis, render_stack
from .gather import DEFAULT_MAX_FRAMES, gather

ISSUES_URL = "https://github.com/lpbas/lldb-why/issues"
_PACKAGE = "why"


def register(debugger, package_name):
    global _PACKAGE
    _PACKAGE = package_name
    debugger.HandleCommand("command script add -o -f %s.lldb_adapter.commands.why_command why" % package_name)
    debugger.HandleCommand("command alias diagnose why")
    # Printed once per lldb session, when ~/.lldbinit imports us.
    print("why %s loaded: run `why` after a crash, `why help` for more" % __version__)


def _parser():
    p = argparse.ArgumentParser(prog="why", add_help=False)
    p.add_argument("action", nargs="?", default="crash",
                   choices=["crash", "stack", "auto", "dump-context", "help", "version"])
    p.add_argument("value", nargs="?")
    p.add_argument("-t", "--thread", type=int, help="thread index (as in `thread list`)")
    p.add_argument("--top", type=int, default=10, help="frames to list in `why stack`")
    p.add_argument("--max-frames", type=int, default=DEFAULT_MAX_FRAMES)
    p.add_argument("--color", dest="color", action="store_true", default=None)
    p.add_argument("--no-color", dest="color", action="store_false")
    p.add_argument("--json", action="store_true", help="print the diagnosis as JSON")
    p.add_argument("--expect", action="store_true", help="dump-context: wrap as a unit test fixture")
    p.add_argument("-o", "--output", help="dump-context: write to this file")
    p.add_argument("--anonymize", action="store_true", help="dump-context: replace your home folder with ~")
    return p


def why_command(debugger, command, exe_ctx, result, internal_dict):
    try:
        args = _parser().parse_args(shlex.split(command))
    except SystemExit:
        result.SetError("usage: why [stack|auto on|off|status|dump-context|help] [-t N] [--color|--no-color]")
        return
    try:
        text = _dispatch(debugger, args)
        if text:
            result.AppendMessage(text.rstrip("\n"))
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
    except UserError as e:
        result.SetError(str(e))
    except Exception:
        result.SetError("why: internal error, please report it at %s\n%s" % (ISSUES_URL, traceback.format_exc()))


class UserError(Exception):
    pass


def _dispatch(debugger, args):
    if args.action == "help":
        return __doc__.strip()
    if args.action == "version":
        return "why %s" % __version__
    if args.action == "auto":
        from . import stophook
        return stophook.command(debugger, args.value or "status", _PACKAGE)

    thread = _thread(debugger, args.thread)
    ctx = gather(debugger, thread=thread, max_frames=args.max_frames)
    color = use_color(debugger, args.color)
    if args.action == "stack":
        report = analyze_stack(ctx, top=args.top)
        if report is None:
            raise UserError("why: the thread has no frames")
        return render_stack(report, color=color)
    if args.action == "dump-context":
        return _dump(ctx, args)
    d = diagnose(ctx)
    if args.json:
        return json.dumps({
            "rule_id": d.rule_id, "verdict": d.verdict, "confidence": d.confidence, "evidence": d.evidence,
            "where": d.where, "notes": d.notes, "next_steps": d.next_steps,
            "user_frame": d.user_frame.to_dict() if d.user_frame else None,
        }, indent=2)
    return render_diagnosis(d, color=color)


def _thread(debugger, index):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess() if target.IsValid() else None
    if process is None or not process.IsValid():
        raise UserError("why: no process. Run the program first.")
    if process.GetState() not in (lldb.eStateStopped, lldb.eStateCrashed, lldb.eStateSuspended):
        raise UserError("why: the process isn't stopped.")
    if index is None:
        return None
    thread = process.GetThreadByIndexID(index)
    if not thread.IsValid():
        raise UserError("why: no thread #%d" % index)
    return thread


def _dump(ctx, args):
    data = ctx.to_dict()
    if args.expect:
        d = diagnose(ctx)
        data = {
            "description": "Captured with `why dump-context --expect`; describe the scenario here.",
            "expect": {"rule_id": d.rule_id, "confidence": d.confidence, "verdict_contains": [d.verdict],
                       "user_frame": d.user_frame.name if d.user_frame else None},
            "context": data,
        }
        if data["expect"]["user_frame"] is None:
            del data["expect"]["user_frame"]
    text = json.dumps(data, indent=1)
    if args.anonymize:
        home = os.path.expanduser("~")
        if home and home != "/":
            text = text.replace(home, "~")
    if args.output:
        with open(os.path.expanduser(args.output), "w") as fh:
            fh.write(text + "\n")
        return "why: wrote %s" % args.output
    return text


def use_color(debugger, requested=None):
    """Plain text unless asked for, or lldb uses color outside Xcode.

    Xcode's console doesn't render ANSI, and runs lldb inside lldb-rpc-server.
    WHY_COLOR=1 / WHY_COLOR=0 overrides everything.
    """
    env = os.environ.get("WHY_COLOR")
    if env is not None:
        return env not in ("0", "", "no", "false")
    if requested is not None:
        return requested
    executable = os.path.basename(getattr(sys, "executable", "") or "")
    if "rpc-server" in executable or os.environ.get("TERM", "dumb") == "dumb":
        return False
    return bool(debugger.GetUseColor())
