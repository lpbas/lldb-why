"""why: plain-English crash explanations in lldb.

Install with one line in ~/.lldbinit:

    command script import /path/to/why

This file must not import lldb at module level, so `why.core` stays importable
(and testable) without a debugger.
"""

__version__ = "0.1.0"


def __lldb_init_module(debugger, internal_dict):
    from .lldb_adapter.commands import register
    register(debugger, __name__)
