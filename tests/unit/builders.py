"""Helpers to build CrashContexts in tests. Values are taken from real probe
runs on arm64 macOS 26 unless noted."""

from why.core.model import CrashContext, Frame, LanguageException, Region, StopInfo, ThreadInfo

APP = "/Users/dev/demo/.build/debug/demo"
PATHS = {
    "libsystem_kernel.dylib": "/usr/lib/system/libsystem_kernel.dylib",
    "libsystem_pthread.dylib": "/usr/lib/system/libsystem_pthread.dylib",
    "libsystem_c.dylib": "/usr/lib/system/libsystem_c.dylib",
    "libsystem_malloc.dylib": "/usr/lib/system/libsystem_malloc.dylib",
    "libswiftCore.dylib": "/usr/lib/swift/libswiftCore.dylib",
    "libswift_Concurrency.dylib": "/usr/lib/swift/libswift_Concurrency.dylib",
    "libdispatch.dylib": "/usr/lib/system/libdispatch.dylib",
    "libobjc.A.dylib": "/usr/lib/libobjc.A.dylib",
    "libc++abi.dylib": "/usr/lib/libc++abi.dylib",
    "CoreFoundation": "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
    "SwiftUI": "/System/Library/Frameworks/SwiftUI.framework/SwiftUI",
    "SwiftUICore": "/System/Library/Frameworks/SwiftUICore.framework/SwiftUICore",
    "AttributeGraph": "/System/Library/PrivateFrameworks/AttributeGraph.framework/AttributeGraph",
    "UIKitCore": "/System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore",
    "dyld": "/usr/lib/dyld",
    "demo": APP,
}

MAIN_STACK = Region(base=0x16F604000, end=0x16FE00000, readable=True, writable=True, mapped=True, type="stack")
UNMAPPED = Region(base=0x1, end=0x100000000)
MASK = 0xFFFF800000000000


def frame(index, name, module="demo", sp=0x16FDFB0A0, pc=None, function=None, file="", line=0, inlined=False):
    return Frame(
        index=index,
        pc=pc if pc is not None else 0x100001000 + index * 4,
        sp=sp,
        function=function if function is not None else name,
        display=name,
        module=module or "",
        module_path=PATHS.get(module, APP if module else ""),
        file=file,
        line=line,
        inlined=inlined,
    )


def stack(*specs, sp0=0x16FDFB000, step=0x40):
    """frames from (name, module) pairs, sp increasing by `step` per frame."""
    out = []
    sp = sp0
    for i, spec in enumerate(specs):
        name, module = spec[0], spec[1]
        out.append(frame(i, name, module, sp=sp, **(spec[2] if len(spec) > 2 else {})))
        sp += step
    return out


def bad_access(frames, fault, code=1, fault_region=None, stack_region=MAIN_STACK, **kw):
    return CrashContext(
        stop=StopInfo(reason="exception", exc_type=1, exc_code=code, exc_subcode=fault, fault_address=fault,
                      description="EXC_BAD_ACCESS (code=%d, address=0x%x)" % (code, fault)),
        thread=kw.pop("thread", ThreadInfo(index=1, queue="com.apple.main-thread", is_main=True)),
        frames=frames,
        total_frames=len(frames),
        address_mask=MASK,
        fault_region=fault_region if fault_region is not None else UNMAPPED,
        stack_region=stack_region,
        main_executable=APP,
        **kw
    )


def trap(frames, description, **kw):
    pc = frames[0].pc
    return CrashContext(
        stop=StopInfo(reason="exception", exc_type=6, exc_code=1, exc_subcode=pc,
                      description=description),
        thread=kw.pop("thread", ThreadInfo(index=1, queue="com.apple.main-thread", is_main=True)),
        frames=frames, total_frames=len(frames), address_mask=MASK, stack_region=MAIN_STACK, **kw)


def instrumentation(frames, message):
    return CrashContext(
        stop=StopInfo(reason="instrumentation", description=message, instrumentation="SwiftRuntimeReporting",
                      instrumentation_message=message, is_fatal=True),
        thread=ThreadInfo(index=1, queue="com.apple.main-thread", is_main=True),
        frames=frames, total_frames=len(frames), address_mask=MASK, stack_region=MAIN_STACK)


def sigabrt(frames, exception=None):
    return CrashContext(
        stop=StopInfo(reason="signal", signal=6, description="signal SIGABRT"),
        thread=ThreadInfo(index=1, queue="com.apple.main-thread", is_main=True),
        frames=frames, total_frames=len(frames), address_mask=MASK, stack_region=MAIN_STACK,
        exception=exception)


ABORT_FRAMES = [
    ("__pthread_kill", "libsystem_kernel.dylib"),
    ("pthread_kill", "libsystem_pthread.dylib"),
    ("abort", "libsystem_c.dylib"),
]


def objc_exception(name, reason, throw_site="main"):
    bt = stack(("__exceptionPreprocess", "CoreFoundation"), ("objc_exception_throw", "libobjc.A.dylib"),
               ("-[NSException raise]", "CoreFoundation"), (throw_site, "demo"), ("start", "dyld"))
    return LanguageException(language="objc", name=name, reason=reason, backtrace=bt)
