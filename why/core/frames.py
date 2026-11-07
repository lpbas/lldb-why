"""Telling user code from system code and compiler-generated helpers."""

import os
import re

# Images under these paths are Apple's, not the user's.
SYSTEM_PATH_PREFIXES = (
    "/System/",
    "/usr/lib/",
    "/usr/libexec/",
    "/Library/Apple/",
    "/Library/Developer/",            # toolchains, CoreSimulator runtimes
    "/Applications/Xcode",            # toolchain dylibs, sanitizer runtimes
    "/private/preboot/Cryptexes/",    # macOS cryptex (Safari / WebKit)
    "/System/Cryptexes/",
)
# Path fragments that mark system images in simulator runtimes and device support folders.
SYSTEM_PATH_FRAGMENTS = (
    "/RuntimeRoot/",
    ".simruntime/",
    "/DeviceSupport/",
    "/Symbols/System/",
    "/Symbols/usr/",
)
# Fallback when only the image name is known (e.g. from an .ips report).
SYSTEM_MODULE_NAMES = frozenset([
    "dyld", "libdyld.dylib", "libobjc.A.dylib", "libdispatch.dylib",
    "libc++abi.dylib", "libc++.1.dylib", "libswiftCore.dylib", "libswift_Concurrency.dylib",
    "CoreFoundation", "Foundation", "UIKitCore", "UIKit", "AppKit", "SwiftUI", "SwiftUICore",
    "AttributeGraph", "QuartzCore", "GraphicsServices", "CoreData", "Combine", "FrontBoardServices",
    "BaseBoard", "RunningBoardServices", "HIToolbox", "CFNetwork", "libxpc.dylib",
])
SYSTEM_MODULE_PREFIXES = ("libsystem_", "libswift", "libclang_rt.")

# Compiler-generated or runtime glue that is never "your code", even when it
# lives in your binary. Matched against both the display name and the full name.
HELPER_PATTERNS = [re.compile(p) for p in (
    r"^outlined ",
    r"^thunk for ",
    r"^reabstraction thunk",
    r"^partial apply",
    r"^merged ",
    r"^__swift_",
    r"^___lldb_unnamed_symbol",
    r"^value witness",
    r"^type metadata ",
    r"^lazy protocol witness",
    r"^protocol witness for ",
    r"^@objc ",
    r"^key path ",
    r"^Swift runtime failure",
    r"^___?chkstk_darwin",
)]


def is_system_module(frame):
    path = frame.module_path or ""
    if path:
        if path.startswith(SYSTEM_PATH_PREFIXES):
            return True
        if any(fragment in path for fragment in SYSTEM_PATH_FRAGMENTS):
            return True
        return False
    name = frame.module or ""
    return name in SYSTEM_MODULE_NAMES or name.startswith(SYSTEM_MODULE_PREFIXES)


def is_helper(frame):
    for text in (frame.display, frame.function):
        if text and any(p.search(text) for p in HELPER_PATTERNS):
            return True
    return False


def is_user_frame(frame):
    return bool(frame.module) and not is_system_module(frame) and not is_helper(frame)


def first_user_frame(frames):
    for frame in frames:
        if is_user_frame(frame):
            return frame
    return None


def helpers_before(frames, user_frame, limit=3):
    """Compiler helpers in the user's own images that sit just above user_frame."""
    if user_frame is None:
        return []
    found = []
    for frame in frames:
        if frame.index >= user_frame.index:
            break
        if frame.module and not is_system_module(frame) and is_helper(frame):
            found.append(frame)
    return found[-limit:]


def frame_label(frame):
    """'#2 deepChain(_:_:) at probe.swift:23 (probe)'"""
    if frame is None:
        return "(no frame)"
    name = frame.name or ("0x%x" % frame.pc)
    text = "#%d %s" % (frame.index, name)
    if frame.file and not frame.file.startswith("<"):   # skip "<compiler-generated>"
        text += " at %s" % os.path.basename(frame.file)
        if frame.line:
            text += ":%d" % frame.line
    if frame.module:
        text += " (%s)" % frame.module
    return text


def matches_any(frame, patterns):
    """True if the frame's display or full name matches one of the regexes."""
    for text in (frame.display, frame.function):
        if text and any(re.search(p, text) for p in patterns):
            return True
    return False


# --- compiler-generated value helpers -------------------------------------------

_OUTLINED = re.compile(r"^outlined (?:init with copy|init with take|copy|assign with copy|assign with take|destroy) of (.+)$")


def outlined_type(frame, qualified=False):
    """The type an "outlined init with copy of T" (and similar) helper works
    on, or None. `qualified` prefers the full name from the debug info
    ("Swift.Optional<App.ListItem.EndContent>") over the display name
    ("ListItem.EndContent?")."""
    names = (frame.function, frame.display) if qualified else (frame.display, frame.function)
    for text in names:
        m = _OUTLINED.match(text or "")
        if m:
            return m.group(1)
    return None


_OPTIONAL = re.compile(r"\bSwift\.Optional<([^<>]*)>")
_MODULE_PREFIX = re.compile(r"(?<![\w.])[A-Za-z_]\w*\.(?=[A-Za-z_])")


def short_type(name):
    """A qualified Swift type name the way Swift code spells it:
    "Swift.Optional<App.ListItem.EndContent>" -> "ListItem.EndContent?"."""
    prev = None
    while prev != name:
        prev, name = name, _OPTIONAL.sub(r"\1?", name)
    return _MODULE_PREFIX.sub("", name)


_DEBUG_PATH = re.compile(r"/Build/Products/Debug(?:-[a-z]+)?/|/\.build/debug/|/\.build/[^/]+/debug/")


def is_unoptimized(frame):
    """True when frame's code was compiled without optimization, from the
    debug info when the adapter recorded it, else from the build layout
    (Xcode's debug dylib, a Debug products folder, SwiftPM's debug folder)."""
    if frame.optimized is not None:
        return not frame.optimized
    return frame.module.endswith(".debug.dylib") or bool(_DEBUG_PATH.search(frame.module_path or ""))
