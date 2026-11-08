"""The `why` lldb command and its subcommands.

    why                  explain the current stop of the crashed (or selected) thread
    why stack            stack usage report for the selected thread (works at any stop)
    why auto on|off      run `why` automatically whenever the process crashes
    why auto status
    why dump-context     print the gathered data as JSON (add --expect for a test fixture)

`diagnose` is the same command under another name. When another lldb
extension (ChatDBG, for one) already uses the name why, only `diagnose` is added.
"""

import argparse
import json
import os
import re
import shlex
import sys
import traceback

import lldb

from .. import __version__
from ..core import analyze_stack, diagnose, render_diagnosis, render_stack
from ..core.anonymize import anonymize, leftovers
from .gather import DEFAULT_MAX_FRAMES, gather

ISSUES_URL = "https://github.com/lpbas/lldb-why/issues"
_PACKAGE = "why"
NAMES = ("why", "diagnose")
# In `help why`, so a later import can tell our command from another extension's.
# No backticks or double quotes: lldb would evaluate or split on them.
MARKER = "(lldb-why)"
HELP = ("Explain the crash in plain English %s. "
        "Subcommands: stack, auto on|off|status, dump-context, help, version." % MARKER)
_name = "why"   # the name the user types, used in hints and usage lines


def register(debugger, package_name):
    global _PACKAGE, _name
    _PACKAGE = package_name
    ci = debugger.GetCommandInterpreter()
    added, taken = [], []
    for name in NAMES:
        if owner(ci, name) == "other":
            taken.append(name)
            continue
        ci.HandleCommand('command script add -o -h "%s" -f %s.lldb_adapter.commands.why_command %s'
                         % (HELP, package_name, name), lldb.SBCommandReturnObject())
        added.append(name)
    print(load_message(added, taken))
    if added:
        _name = added[0]


def owner(ci, name):
    """'free', 'ours' or 'other' for an lldb command name."""
    if not (ci.CommandExists(name) or ci.UserCommandExists(name) or ci.AliasExists(name)):
        return "free"
    result = lldb.SBCommandReturnObject()
    ci.HandleCommand("help %s" % name, result)
    return "ours" if MARKER in (result.GetOutput() or "") else "other"


def load_message(added, taken):
    """Printed once per lldb session, when ~/.lldbinit imports us."""
    if not added:
        return ("why %s not loaded: `why` and `diagnose` both belong to other lldb extensions"
                % __version__)
    name = added[0]
    text = "why %s loaded: run `%s` after a crash, `%s help` for more" % (__version__, name, name)
    if "why" in taken:
        text += ("\nwhy: another lldb extension (ChatDBG, for one) already owns `why`, "
                 "so this one is `diagnose`")
    return text


def renamed(text):
    """why's hints say `why stack`, `why help`...; use the name the user has."""
    if _name == "why" or not text:
        return text
    return _WHY.sub(lambda m: m.group(1) + _name, text)


# `why stack`, "usage: why ...", and the indented lines of `why help`;
# not "why 0.1.0" or "why: ...", where why is the tool's name.
_WHY = re.compile(r"(`|\busage: |^[ \t]+)why(?=[ `]|$)", re.M)
_HELP_ROW = re.compile(r"^(    \S.*?) {2,}(\S.*)$")


def _help_text():
    """The module docstring with the user's command name, columns kept aligned."""
    column = max(len(m.group(1)) for m in map(_HELP_ROW.match, renamed(__doc__).splitlines()) if m) + 2
    lines = []
    for line in renamed(__doc__.strip()).splitlines():
        m = _HELP_ROW.match(line)
        lines.append(m.group(1).ljust(column) + m.group(2) if m else line)
    return "\n".join(lines)


class _Parser(argparse.ArgumentParser):
    def error(self, message):   # argparse would print to stderr and exit
        raise UserError("why: %s" % message)


def _parser():
    p = _Parser(prog="why", add_help=False)
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
    p.add_argument("--anonymize", action="store_true",
                   help="dump-context: rename your code's symbols, paths and messages so the dump can be shared")
    return p


def why_command(debugger, command, exe_ctx, result, internal_dict):
    try:
        args = _parser().parse_args(shlex.split(command))
    except UserError as e:
        result.SetError(renamed("%s\nusage: why [stack|auto on|off|status|dump-context|help] [-t N] "
                                "[--color|--no-color]" % e))
        return
    try:
        text = _dispatch(debugger, args)
        if text:
            result.AppendMessage(renamed(text.rstrip("\n")))
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
    except UserError as e:
        result.SetError(str(e))
    except Exception:
        result.SetError("why: internal error, please report it at %s\n%s" % (ISSUES_URL, _hide_home(traceback.format_exc())))


def _hide_home(text):
    """Tracebacks name files under the user's home folder (their username)."""
    home = os.path.expanduser("~")
    return text.replace(home, "~") if home and home != "/" else text


class UserError(Exception):
    pass


def _dispatch(debugger, args):
    if args.action == "help":
        return _help_text()
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
    report = originals = None
    if args.anonymize:
        ctx, report, originals = anonymize(ctx, home=os.path.expanduser("~"))
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
        text = _hide_home(text)
        # Check the app's data only: why's own words ("why", "Stack", ...) can
        # match a name from the app without leaking anything.
        left = leftovers(_hide_home(json.dumps(ctx.to_dict())), originals)
        if left:
            raise UserError("why: not writing the dump: %d name(s) from your code survived --anonymize. "
                            "Please report this bug at %s (without the dump)." % (len(left), ISSUES_URL))
    if not args.output:
        return text
    with open(os.path.expanduser(args.output), "w") as fh:
        fh.write(text + "\n")
    lines = ["why: wrote %s" % args.output]
    if report is not None:
        lines += ["  " + line for line in report.lines()]
        lines.append("Read it before sharing: messages and names from Apple frameworks are kept.")
    else:
        lines.append("It contains symbol names, paths and messages from your app. "
                     "Use --anonymize before sharing it.")
    return "\n".join(lines)


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
