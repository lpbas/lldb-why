"""Plain data structures shared by the classifier, the stack analyzer and the
LLDB adapter.

Nothing here imports lldb. A CrashContext can be built from a live debugger
session, from a JSON fixture, or (later) from an .ips crash report.
"""

from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional


def _to_int(value):
    if value is None:
        return None
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


class _Serializable:
    """Minimal JSON round-tripping for the dataclasses below.

    _HEX lists int fields written as "0x..." strings so fixtures stay readable.
    _HEX_DICT lists dict fields whose values are ints written as hex.
    _NESTED maps a field to its dataclass, or to [dataclass] for lists.
    Unknown keys are ignored so older fixtures keep loading.
    """

    _HEX = ()
    _HEX_DICT = ()
    _NESTED = {}

    def to_dict(self):
        out = {}
        for f in fields(self):
            value = getattr(self, f.name)
            nested = self._NESTED.get(f.name)
            if value is None:
                out[f.name] = None
            elif isinstance(nested, list):
                out[f.name] = [item.to_dict() for item in value]
            elif nested is not None:
                out[f.name] = value.to_dict()
            elif f.name in self._HEX:
                out[f.name] = hex(value)
            elif f.name in self._HEX_DICT:
                out[f.name] = {k: hex(v) for k, v in value.items()}
            else:
                out[f.name] = value
        return out

    @classmethod
    def from_dict(cls, data):
        kwargs = {}
        names = {f.name for f in fields(cls)}
        for key, value in (data or {}).items():
            if key not in names:
                continue
            nested = cls._NESTED.get(key)
            if value is None:
                kwargs[key] = None
            elif isinstance(nested, list):
                kwargs[key] = [nested[0].from_dict(item) for item in value]
            elif nested is not None:
                kwargs[key] = nested.from_dict(value)
            elif key in cls._HEX:
                kwargs[key] = _to_int(value)
            elif key in cls._HEX_DICT:
                kwargs[key] = {k: _to_int(v) for k, v in value.items()}
            else:
                kwargs[key] = value
        return cls(**kwargs)


@dataclass
class Frame(_Serializable):
    index: int = 0
    pc: int = 0
    sp: int = 0
    function: str = ""      # full demangled name, e.g. "probe.deepChain(probe.ListItem, Swift.Int) -> Swift.Int"
    display: str = ""       # short name, e.g. "deepChain(_:_:)"
    module: str = ""        # image file name; "" when the pc is not in any image
    module_path: str = ""   # full image path, used to tell system code from user code
    inlined: bool = False
    file: str = ""
    line: int = 0
    optimized: Optional[bool] = None   # from the debug info; None when unknown (no debug info, older fixtures)

    _HEX = ("pc", "sp")

    @property
    def name(self):
        return self.display or self.function or ""


@dataclass
class Region(_Serializable):
    """A memory region, plus what we know about the address that was looked up."""

    base: int = 0
    end: int = 0
    readable: bool = False
    writable: bool = False
    executable: bool = False
    mapped: bool = False
    type: str = ""      # debugserver's label: "stack", "heap,malloc-small", ... ("" if unknown)
    image: str = ""     # image containing the address, if any
    section: str = ""   # section containing the address, e.g. "__TEXT.__cstring"

    _HEX = ("base", "end")

    @property
    def size(self):
        return self.end - self.base

    @property
    def perms(self):
        return ("r" if self.readable else "-") + ("w" if self.writable else "-") + ("x" if self.executable else "-")

    def contains(self, address):
        return address is not None and self.base <= address < self.end

    @property
    def is_heap(self):
        t = self.type.lower()
        return "heap" in t or "malloc" in t


@dataclass
class StopInfo(_Serializable):
    reason: str = "exception"   # exception | signal | instrumentation | breakpoint | trace | other
    description: str = ""       # lldb's stop description, verbatim
    exc_type: Optional[int] = None      # Mach exception type (1 = EXC_BAD_ACCESS, 6 = EXC_BREAKPOINT, ...)
    exc_code: Optional[int] = None
    exc_subcode: Optional[int] = None
    signal: Optional[int] = None
    fault_address: Optional[int] = None  # the address that could not be accessed (bad access only)
    instrumentation: str = ""            # e.g. "SwiftRuntimeReporting"
    instrumentation_message: str = ""    # e.g. "Fatal error: Index out of range"
    is_fatal: bool = False

    _HEX = ("exc_code", "exc_subcode", "fault_address")


@dataclass
class ThreadInfo(_Serializable):
    index: int = 1
    name: str = ""
    queue: str = ""
    is_main: bool = False

    @property
    def label(self):
        parts = ["thread #%d" % self.index]
        if self.name:
            parts.append(repr(self.name))
        if self.queue:
            parts.append("queue %s" % self.queue)
        return ", ".join(parts)


@dataclass
class LayoutPart(_Serializable):
    """One step into a value: a stored property, tuple element or enum case."""

    name: str = ""
    type: str = ""
    size: int = 0
    is_case: bool = False   # an enum case (the one the value currently holds)


@dataclass
class ValueLayout(_Serializable):
    """The size of a value found in the crashed thread's frames, measured by
    lldb from the type metadata (no code runs in the process), and the chain
    of its largest parts."""

    type: str = ""          # as lldb names it, e.g. "Swift.Optional<App.ListItem.EndContent>"
    size: int = 0
    variable: str = ""      # where it was read, e.g. "template.end"
    frame_index: int = 0
    parts: List[LayoutPart] = field(default_factory=list)   # largest child, then its largest child, ...

    _NESTED = {"parts": [LayoutPart]}


@dataclass
class LanguageException(_Serializable):
    """An Objective-C / C++ exception that was in flight."""

    language: str = "objc"
    name: str = ""
    reason: str = ""
    backtrace: List[Frame] = field(default_factory=list)  # where it was thrown

    _NESTED = {"backtrace": [Frame]}


@dataclass
class CrashContext(_Serializable):
    stop: StopInfo = field(default_factory=StopInfo)
    thread: ThreadInfo = field(default_factory=ThreadInfo)
    frames: List[Frame] = field(default_factory=list)
    total_frames: int = 0        # can exceed len(frames) when the adapter capped the walk
    arch: str = "arm64"          # arm64 | arm64e | x86_64
    platform: str = "macos"      # macos | ios | ios-simulator | ...
    address_mask: Optional[int] = None   # bits that are NOT part of an address, e.g. 0xffff800000000000
    pagezero_end: int = 0x100000000
    registers: Dict[str, int] = field(default_factory=dict)   # frame 0, a few interesting ones
    fault_region: Optional[Region] = None
    pc_region: Optional[Region] = None
    stack_region: Optional[Region] = None   # the selected thread's stack (mapped part, no guard)
    exception: Optional[LanguageException] = None
    caller_prologue: List[List[str]] = field(default_factory=list)  # [[mnemonic, operands], ...] of frame 1, up to its pc
    main_executable: str = ""
    copied_value: Optional[ValueLayout] = None   # the value an outlined copy helper was copying at a chkstk crash

    _HEX = ("address_mask", "pagezero_end")
    _HEX_DICT = ("registers",)
    _NESTED = {
        "stop": StopInfo,
        "thread": ThreadInfo,
        "frames": [Frame],
        "fault_region": Region,
        "pc_region": Region,
        "stack_region": Region,
        "exception": LanguageException,
        "copied_value": ValueLayout,
    }

    @property
    def frames_truncated(self):
        return self.total_frames > len(self.frames)


@dataclass
class Diagnosis:
    rule_id: str
    verdict: str
    confidence: str                  # high | medium | low
    evidence: List[str] = field(default_factory=list)
    where: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    user_frame: Optional[Frame] = None
    stack: Any = None                # StackReport, when the stack analyzer ran
