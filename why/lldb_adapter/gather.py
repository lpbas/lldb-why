"""Collects a CrashContext from a live lldb session through the SB API.

All lldb-specific knowledge lives here; the core never imports lldb.
"""

import json
import re

import lldb

from ..core.frames import outlined_type
from ..core.model import (CrashContext, Frame, LanguageException, LayoutPart, Region, StopInfo, ThreadInfo,
                           ValueLayout)
from ..core.stack import is_chkstk

DEFAULT_MAX_FRAMES = 250000   # an 8 MB stack of 48-byte frames is ~175k frames
REGISTERS = ("x9", "x15", "x16", "x17", "fp", "lr", "sp", "pc", "rax", "rbp", "rsp", "rip")

_STOP_REASONS = {
    lldb.eStopReasonException: "exception",
    lldb.eStopReasonSignal: "signal",
    lldb.eStopReasonInstrumentation: "instrumentation",
    lldb.eStopReasonBreakpoint: "breakpoint",
    lldb.eStopReasonWatchpoint: "watchpoint",
    lldb.eStopReasonTrace: "trace",
    lldb.eStopReasonPlanComplete: "plan",
}
CRASH_REASONS = ("exception", "signal", "instrumentation")


def stop_reason_name(thread):
    return _STOP_REASONS.get(thread.GetStopReason(), "other")


def crashed_thread(process):
    """The selected thread, unless another thread is the one that crashed."""
    selected = process.GetSelectedThread()
    if selected.IsValid() and stop_reason_name(selected) in CRASH_REASONS:
        return selected
    for thread in process:
        if stop_reason_name(thread) in ("exception", "instrumentation"):
            return thread
    return selected


def gather(debugger, thread=None, max_frames=DEFAULT_MAX_FRAMES):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    if thread is None:
        thread = crashed_thread(process)

    ctx = CrashContext()
    ctx.arch, ctx.platform = _arch_and_platform(target.GetTriple() or "")
    ctx.stop = _stop_info(thread)
    ctx.thread = ThreadInfo(index=thread.GetIndexID(), name=thread.GetName() or "",
                            queue=thread.GetQueueName() or "", is_main=thread.GetIndexID() == 1)

    total = thread.GetNumFrames()
    ctx.total_frames = total
    ctx.frames = [_frame(thread.GetFrameAtIndex(i), i) for i in range(min(total, max_frames))]
    ctx.address_mask = _address_mask(process)
    ctx.main_executable, ctx.pagezero_end = _main_executable(target)

    if ctx.frames:
        ctx.registers = _registers(thread.GetFrameAtIndex(0))
    probe = _RegionProbe(debugger, process, target)
    if ctx.stop.fault_address is not None:
        ctx.fault_region = probe.region(ctx.stop.fault_address)
    if ctx.frames:
        ctx.pc_region = probe.region(ctx.frames[0].pc)
        ctx.stack_region = _stack_region(probe, ctx.frames)
    if ctx.stop.reason in ("signal", "exception"):
        ctx.exception = _language_exception(thread)
    if len(ctx.frames) > 1 and is_chkstk(ctx.frames[0]):
        ctx.caller_prologue = _prologue(target, thread.GetFrameAtIndex(1))
        ctx.copied_value = _copied_value(thread, ctx.frames)
    return ctx


# --- pieces --------------------------------------------------------------------------

def _arch_and_platform(triple):
    parts = triple.split("-")
    arch = parts[0] if parts else "arm64"
    os_part = parts[2] if len(parts) > 2 else ""
    env = parts[3] if len(parts) > 3 else ""
    platform = re.sub(r"[\d.]+$", "", os_part) or "unknown"
    platform = {"macosx": "macos"}.get(platform, platform)
    if env.startswith("simulator"):
        platform += "-simulator"
    elif env.startswith("macabi"):
        platform = "mac-catalyst"
    return arch, platform


def _stop_info(thread):
    reason = stop_reason_name(thread)
    stop = StopInfo(reason=reason, description=thread.GetStopDescription(1024) or "")
    data = [thread.GetStopReasonDataAtIndex(i) for i in range(thread.GetStopReasonDataCount())]
    if reason == "exception" and data:
        stop.exc_type = data[0]
        stop.exc_code = data[1] if len(data) > 1 else None
        stop.exc_subcode = data[2] if len(data) > 2 else None
        if stop.exc_type == 1 and stop.exc_subcode is not None:   # EXC_BAD_ACCESS: subcode is the address
            stop.fault_address = stop.exc_subcode
    elif reason == "signal" and data:
        stop.signal = data[0]
    elif reason == "instrumentation":
        stream = lldb.SBStream()
        thread.GetStopReasonExtendedInfoAsJSON(stream)
        try:
            info = json.loads(stream.GetData() or "{}")
        except ValueError:
            info = {}
        stop.instrumentation = info.get("instrumentation_class", "")
        stop.instrumentation_message = info.get("description", "") or stop.description
        stop.is_fatal = bool(info.get("is_fatal", False))
        address = info.get("memory_address") or info.get("address")
        if address:
            stop.fault_address = int(address)
    return stop


def _frame(f, index):
    module = f.GetModule()
    spec = module.GetFileSpec() if module.IsValid() else None
    line_entry = f.GetLineEntry()
    function = f.GetFunction()
    file, line = "", 0
    if line_entry.IsValid() and line_entry.GetFileSpec().IsValid():
        file = line_entry.GetFileSpec().fullpath or ""
        line = line_entry.GetLine()
    return Frame(
        index=index,
        pc=f.GetPC(),
        sp=f.GetSP(),
        function=f.GetFunctionName() or "",
        display=f.GetDisplayFunctionName() or "",
        module=(spec.GetFilename() if spec else "") or "",
        module_path=(spec.fullpath if spec else "") or "",
        inlined=f.IsInlined(),
        file=file,
        line=line,
        optimized=function.GetIsOptimized() if function.IsValid() else None,
    )


def _registers(frame):
    out = {}
    for group in frame.GetRegisters():
        for reg in group:
            name = reg.GetName()
            if name in REGISTERS and name not in out:
                value = reg.GetValueAsUnsigned(0xFFFFFFFFFFFFFFFF)
                if value != 0xFFFFFFFFFFFFFFFF:
                    out[name] = value
        if group.GetName() and "General" in group.GetName():
            break
    return out


def _address_mask(process):
    if not hasattr(process, "GetAddressMask"):
        return None
    try:
        mask = process.GetAddressMask(lldb.eAddressMaskTypeData)
    except Exception:
        return None
    invalid = getattr(lldb, "LLDB_INVALID_ADDRESS_MASK", 0xFFFFFFFFFFFFFFFF)
    if not mask or mask == invalid:
        return None
    return mask


def _main_executable(target):
    module = target.GetModuleAtIndex(0)
    path = module.GetFileSpec().fullpath if module.IsValid() else ""
    pagezero_end = 0x100000000
    if module.IsValid():
        section = module.FindSection("__PAGEZERO")
        if section.IsValid() and section.GetByteSize():
            pagezero_end = section.GetFileAddress() + section.GetByteSize()
    return path or "", pagezero_end


class _RegionProbe:
    """SBMemoryRegionInfo plus the region type debugserver reports in the raw
    qMemoryRegionInfo packet (SBMemoryRegionInfo.GetName() is always empty on
    Darwin), plus the image section containing the address."""

    _TYPE = re.compile(r"type:([^;]+);")

    def __init__(self, debugger, process, target):
        self.debugger = debugger
        self.process = process
        self.target = target
        self.packets = process.GetPluginName() == "gdb-remote"

    def region(self, address):
        info = lldb.SBMemoryRegionInfo()
        if self.process.GetMemoryRegionInfo(address, info).Fail():
            return None
        region = Region(base=info.GetRegionBase(), end=info.GetRegionEnd(), readable=info.IsReadable(),
                        writable=info.IsWritable(), executable=info.IsExecutable(), mapped=info.IsMapped(),
                        type=info.GetName() or "")
        if not region.type and self.packets and region.mapped:
            region.type = self._packet_type(address)
        resolved = self.target.ResolveLoadAddress(address)
        section = resolved.GetSection()
        if section.IsValid():
            names = []
            while section.IsValid():
                names.insert(0, section.GetName())
                section = section.GetParent()
            region.section = ".".join(names)
            region.image = resolved.GetModule().GetFileSpec().GetFilename() or ""
        return region

    def _packet_type(self, address):
        result = lldb.SBCommandReturnObject()
        self.debugger.GetCommandInterpreter().HandleCommand(
            "process plugin packet send qMemoryRegionInfo:%x" % address, result)
        match = self._TYPE.search(result.GetOutput() or "")
        return match.group(1) if match else ""


def _stack_region(probe, frames):
    """The mapped region holding this thread's stack. Frame 0's sp can already
    be inside the guard page, so start from the outermost frame."""
    for frame in reversed(frames):
        if frame.sp == 0:
            continue
        region = probe.region(frame.sp)
        if region is not None and region.mapped and region.writable and region.contains(frame.sp):
            return region
    return None


def _language_exception(thread):
    if not hasattr(thread, "GetCurrentException"):
        return None
    value = thread.GetCurrentException()
    if not value.IsValid() or value.GetValueAsUnsigned() == 0:
        return None
    type_name = value.GetTypeName() or ""
    exc = LanguageException(language="objc" if "NS" in type_name or "id" == type_name else "c++")
    name = value.GetChildMemberWithName("name")
    if name.IsValid():
        exc.name = (name.GetSummary() or "").strip('"@')
    reason = value.GetChildMemberWithName("reason")
    exc.reason = ((reason.GetSummary() if reason.IsValid() else None) or value.GetSummary() or "").strip('"@')
    if not exc.name and exc.language == "c++":
        exc.name = type_name
    if hasattr(thread, "GetCurrentExceptionBacktrace"):
        backtrace = thread.GetCurrentExceptionBacktrace()
        if backtrace.IsValid():
            exc.backtrace = [_frame(backtrace.GetFrameAtIndex(i), i) for i in range(min(backtrace.GetNumFrames(), 64))]
    return exc


def _prologue(target, caller):
    """Instructions of the chkstk caller from its entry up to (not including)
    the call, as [mnemonic, operands] pairs."""
    symbol = caller.GetSymbol()
    if not symbol.IsValid():
        return []
    start = symbol.GetStartAddress().GetLoadAddress(target)
    call_return = caller.GetPC()
    if start == lldb.LLDB_INVALID_ADDRESS or not start < call_return <= start + 4096:
        return []
    width = 4 if target.GetTriple().startswith("arm64") else 1
    instructions = target.ReadInstructions(symbol.GetStartAddress(), (call_return - start) // width + 2)
    out = []
    for i in range(instructions.GetSize()):
        ins = instructions.GetInstructionAtIndex(i)
        address = ins.GetAddress().GetLoadAddress(target)
        if address >= call_return:
            break
        out.append([ins.GetMnemonic(target) or "", ins.GetOperands(target) or ""])
    return out[:-1]  # drop the call itself


# --- size of the value an outlined copy helper was copying -------------------------

LAYOUT_SEARCH_FRAMES = 6    # frames above the helper to look for a variable of that type
LAYOUT_MAX_CHILDREN = 64
LAYOUT_DEPTH = 4


def _copied_value(thread, frames):
    """At a chkstk crash in "outlined init with copy of T", finds a variable of
    type T in the frames above and measures it. lldb computes the size from
    the type metadata, so no code runs in the crashed process. Swift types
    can't be sized from SBType alone (FindFirstType misses them and their
    static byte size is 0), but SBValue.GetByteSize() works."""
    if len(frames) < 2 or not is_chkstk(frames[0]):
        return None
    wanted = outlined_type(frames[1], qualified=True)
    if not wanted:
        return None
    names = {wanted, "Swift.Optional<%s>" % wanted}
    m = re.match(r"^Swift\.Optional<(.*)>$", wanted)
    if m:
        names.add(m.group(1))
    try:
        for index in range(2, min(len(frames), 2 + LAYOUT_SEARCH_FRAMES)):
            frame = thread.GetFrameAtIndex(index)
            # Arguments first: locals may not be initialized yet.
            for arguments, locals_ in ((True, False), (False, True)):
                # eDynamicDontRunTarget: resolve dynamic types without running code in
                # the app, whatever the user's target.prefer-dynamic-value setting is.
                values = frame.GetVariables(arguments, locals_, False, True, lldb.eDynamicDontRunTarget)
                for k in range(values.GetSize()):
                    found = _find_value(values.GetValueAtIndex(k), names, depth=1)
                    if found is not None:
                        path, value = found
                        return _layout(value, path, index)
    except Exception:  # never let an optional extra break the diagnosis
        return None
    return None


def _find_value(value, names, depth):
    """value, or one of its stored properties, if its type is one of `names`."""
    if not value.IsValid():
        return None
    if (value.GetTypeName() or "") in names and value.GetByteSize():
        return value.GetName() or "", value
    if depth and value.GetType().GetTypeClass() == lldb.eTypeClassStruct:
        for i in range(min(value.GetNumChildren(), LAYOUT_MAX_CHILDREN)):
            found = _find_value(value.GetChildAtIndex(i), names, depth - 1)
            if found is not None:
                return "%s.%s" % (value.GetName() or "", found[0]), found[1]
    return None


def _layout(value, variable, frame_index):
    """The value's size, then its largest part while that part is most of it."""
    layout = ValueLayout(type=value.GetTypeName() or "", size=value.GetByteSize(), variable=variable,
                         frame_index=frame_index)
    current = value
    for _ in range(LAYOUT_DEPTH):
        children = [current.GetChildAtIndex(i) for i in range(min(current.GetNumChildren(), LAYOUT_MAX_CHILDREN))]
        children = [c for c in children if c.IsValid()]
        if not children:
            break
        biggest = max(children, key=lambda c: c.GetByteSize())
        size = biggest.GetByteSize()
        if size < 256 or size * 2 < current.GetByteSize():
            break
        layout.parts.append(LayoutPart(
            name=biggest.GetName() or "", type=biggest.GetTypeName() or "", size=size,
            is_case=current.GetType().GetTypeClass() == lldb.eTypeClassUnion))
        current = biggest
    return layout
