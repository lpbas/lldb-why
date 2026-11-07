"""Removes what identifies the user's app from a CrashContext, so a dump can
be shared in a public issue or committed as a test fixture.

What changes:
  * Frames in the user's code (anything that isn't an Apple system image):
    every identifier that isn't an Apple, Swift or compiler word becomes a
    placeholder (Module1, Type3, name2), consistently everywhere it appears.
    Paths become /redacted/<renamed file name>.
  * Apple frames keep their names, but the user's types inside them (SwiftUI
    generics such as `ModifiedContent<MyApp.FooView, ...>`) are renamed too.
  * Crash messages, exception reasons and non-Apple queue and thread names
    keep only the known Swift / Foundation phrases the rules look for.
  * The home folder becomes ~.
What stays: Apple frame names, addresses, stack pointers, sizes, registers,
the stop reason, and the classification (rule and confidence).

`leftovers(text)` lists original names that are still in a rendered dump;
callers refuse to write the file if it returns anything.
"""

import copy
import re

from . import frames as F
from .model import Frame
from .rules import NSEXCEPTION_HINTS, SWIFT_MESSAGES

REDACTED_DIR = "/redacted"
REDACTED = "<redacted>"

# Words that are part of the language, the demangler's output or common
# compiler-generated names. Anything else in the user's frames is renamed.
KEEP_WORDS = frozenset("""
    outlined init with copy take assign destroy consume retain release enum tag store of in for to from at as is
    closure implicit thunk helper reabstraction partial apply protocol witness conformance merged specialized generic
    specialization signature static objc escaping callee_guaranteed callee_owned guaranteed owned unowned weak
    getter setter modify read didset willset didSet willSet unsafeAddressor unsafeMutableAddressor lazy variable
    initializer deinit subscript type metadata accessor completion function value table key path main body
    opaque return some any where Self self throws rethrows async await inout let var nil true false resume
    suspend dispatch block invoke _block_invoke Swift runtime failure Fatal error Precondition failed Assertion
    debug dylib swift framework app so a dylib c cc cpp m mm h hpp o
    int char void long unsigned short signed const struct union class bool float double size_t auto operator
    std __1 Builtin
    Int Int8 Int16 Int32 Int64 UInt UInt8 UInt16 UInt32 UInt64 Float Double Float16 Bool String Substring
    Character Array ContiguousArray ArraySlice Dictionary Set Optional Result Void Never Error Any AnyObject
    AnyHashable AnyClass Sendable Equatable Hashable Comparable Codable Encodable Decodable Identifiable
    Sequence Collection IteratorProtocol Range ClosedRange StaticString Unmanaged UnsafePointer
    UnsafeMutablePointer UnsafeRawPointer UnsafeMutableRawPointer UnsafeBufferPointer UnsafeMutableBufferPointer
    OpaquePointer Task TaskGroup MainActor Actor CheckedContinuation UnsafeContinuation Element Wrapped Key
    Value Body Content Label View Scene App Data Date URL UUID NSObject NSString NSArray NSDictionary
""".split())

APPLE_MODULES = frozenset("""
    Swift SwiftUI SwiftUICore Foundation UIKit UIKitCore AppKit CoreGraphics CoreFoundation Combine Observation
    _Concurrency Dispatch ObjectiveC Darwin os CoreData QuartzCore AttributeGraph _StringProcessing __C Builtin
    XCTest Testing SwiftData CoreLocation MapKit AVFoundation WebKit Network StoreKit CloudKit Photos PhotosUI
""".split())

def _rule_words():
    """English words the rules match in messages, and the model's field names:
    keeping them avoids renaming `end` or `index` in one place while the same
    word stays elsewhere. None of them identifies an app."""
    from dataclasses import fields
    from . import model
    from .rules import CLIENT_BUGS
    words = set()
    for table in (SWIFT_MESSAGES, NSEXCEPTION_HINTS, CLIENT_BUGS):
        for entry in table:
            words.update(w for w in re.findall(r"[A-Za-z_]{2,}", entry[0]))
    for name in dir(model):
        cls = getattr(model, name)
        if isinstance(cls, type) and hasattr(cls, "__dataclass_fields__"):
            words.update(f.name for f in fields(cls))
    return frozenset(words | {"arithmetic", "overflow", "range", "bounds", "found", "unwrapping", "implicitly",
                              "division", "zero", "Index", "out"})


_RULE_WORDS = _rule_words()

# Short words that rules match in messages; everything else in a message goes.
_MESSAGE_PREFIX = re.compile(r"^(Fatal error|Precondition failed|Assertion failed|Swift runtime failure|"
                             r"Main Thread Checker|warning: data race detected)(: |$)")
_IDENT = re.compile(r"(?<![0-9A-Za-z_])[A-Za-z_][A-Za-z0-9_]*")
_GENERIC_PARAM = re.compile(r"^_\d+(?:_\d+)*$")        # the `_0_0` of `τ_0_0`
_CHAIN = re.compile(r"(?<![\w.])([A-Za-z_]\w*)((?:\.[A-Za-z_]\w*)+)")
_PATH = re.compile(r"(?:~|/)[^\s:\"',)]*/[^\s:\"',)]*")


class Report:
    """What was changed, without the original names (safe to print)."""

    def __init__(self):
        self.modules = 0
        self.names = 0
        self.messages = 0
        self.queues = 0

    def lines(self):
        return ["renamed %d module(s) and %d other name(s) from your code" % (self.modules, self.names),
                "redacted %d message(s) and %d queue/thread name(s)" % (self.messages, self.queues),
                "kept: Apple frame names, addresses, stack pointers, sizes, registers"]


class _Anonymizer:
    def __init__(self, ctx, home):
        self.ctx = ctx
        self.home = home if home and home != "/" else None
        self.map = {}
        self.placeholders = set()
        self.counts = {"Module": 0, "Type": 0, "name": 0}
        self.report = Report()
        frames = list(ctx.frames) + (list(ctx.exception.backtrace) if ctx.exception else [])
        self.user = [f for f in frames if not F.is_system_module(f)]
        self.system = [f for f in frames if F.is_system_module(f)]
        self.apple_modules = APPLE_MODULES | {self._stem(f.module) for f in self.system if f.module}
        self.user_modules = self._find_user_modules()
        for module in sorted(self.user_modules):
            self._placeholder(module, kind="Module")
        self.apple_words = self._apple_words()

    # --- vocabulary ---

    @staticmethod
    def _stem(name):
        return (name or "").split("/")[-1].split(".")[0]

    def _find_user_modules(self):
        mods = set()
        for f in self.user:
            stem = self._stem(f.module)
            if stem and stem not in self.apple_modules:
                mods.add(stem)
            for m in _CHAIN.finditer(f.function or ""):   # qualified names only; display names drop the module
                if m.group(1) not in self.apple_modules:
                    mods.add(m.group(1))
        exe = self._stem(self.ctx.main_executable)
        if exe and not self._is_system_path(self.ctx.main_executable):
            mods.add(exe)
        # Only names that look like modules: a qualifier like `self` or a
        # lowercase local isn't one.
        return {m for m in mods if m and m not in KEEP_WORDS}

    def _apple_words(self):
        """Identifiers in Apple frames' qualified names, minus `UserModule.X.Y`
        chains. Display names are not used: they mention the user's types
        unqualified (`ModifiedContent<FooView, ...>`)."""
        words = set()
        for f in self.system:
            text = _CHAIN.sub(lambda m: "" if m.group(1) in self.user_modules else m.group(0), f.function or "")
            words.update(_IDENT.findall(text))
        return words - set(self.map)

    @staticmethod
    def _is_system_path(path):
        """Also takes a bare image name (regions record `libsystem_kernel.dylib`)."""
        if not path:
            return False
        if "/" not in path:
            return F.is_system_module(Frame(module=path))
        return F.is_system_module(Frame(module_path=path))

    # --- renaming ---

    def _placeholder(self, word, kind=None):
        if word in self.map:
            return self.map[word]
        if kind is None:
            kind = "Type" if word.lstrip("_")[:1].isupper() else "name"
        self.counts[kind] += 1
        self.map[word] = "%s%d" % (kind, self.counts[kind])
        self.placeholders.add(self.map[word])
        if kind == "Module":
            self.report.modules += 1
        else:
            self.report.names += 1
        return self.map[word]

    def _keep(self, word):
        return (word in KEEP_WORDS or word in self.placeholders or word in _RULE_WORDS or word in self.apple_words or bool(_GENERIC_PARAM.match(word))
                or word.startswith("___lldb_unnamed_symbol") or word.startswith("___chkstk"))

    def _rename_user_chains(self, text):
        """`UserModule.A.B` -> every component renamed (accessor words such as
        `getter` or `init` stay), wherever it appears."""
        def sub(m):
            if m.group(1) not in self.user_modules:
                return m.group(0)
            parts = [m.group(1)] + m.group(2).split(".")[1:]
            return ".".join(p if (i and self._keep(p)) else self._placeholder(p) for i, p in enumerate(parts))
        return _CHAIN.sub(sub, text)

    def user_text(self, text):
        """Text from the user's own code: rename everything not on an allowlist."""
        if not text:
            return text
        if text.startswith("Swift runtime failure: "):
            return "Swift runtime failure: " + self.message(text[len("Swift runtime failure: "):], count=False)
        text = self._rename_user_chains(text)
        return _IDENT.sub(lambda m: m.group(0) if self._keep(m.group(0)) else self._placeholder(m.group(0)), text)

    def other_text(self, text):
        """Text from Apple code or lldb: rename only names known to be the user's."""
        if not text:
            return text
        text = self._rename_user_chains(text)
        text = _IDENT.sub(lambda m: self.map.get(m.group(0), m.group(0)), text)
        return self.path_text(text)

    def path_text(self, text):
        if self.home:
            text = text.replace(self.home, "~")
        return text

    def path(self, path):
        """A file or image path: Apple's stay (home folder -> ~), the user's are redacted."""
        if not path or path.startswith("<") or path.startswith("/<"):
            return path
        if self._is_system_path(path):
            return self.path_text(path)
        return "%s/%s" % (REDACTED_DIR, self.user_text(path.rstrip("/").split("/")[-1]))

    def message(self, text, patterns=None, count=True):
        """Keep a known prefix and the phrases rules look for; drop the rest."""
        if not text:
            return text
        if patterns is None:
            patterns = [p for p, _, _ in SWIFT_MESSAGES]
        prefix = _MESSAGE_PREFIX.match(text)
        kept = [m.group(0) for m in (re.search(p, text) for p in patterns) if m]
        out = (prefix.group(1) + ": " if prefix else "") + (" ... ".join(kept) if kept else REDACTED)
        if out != text and count:
            self.report.messages += 1
        return out

    def label(self, name):
        if not name or name.startswith("com.apple."):
            return name
        self.report.queues += 1
        return REDACTED

    # --- the context ---

    def frame(self, f):
        system = F.is_system_module(f)
        if system:
            f.function, f.display, f.file = self.other_text(f.function), self.other_text(f.display), self.path_text(f.file)
            f.module_path = self.path_text(f.module_path)
            return
        f.function, f.display = self.user_text(f.function), self.user_text(f.display)
        f.file = self.path(f.file)
        f.module = self.user_text(f.module)
        f.module_path = self.path(f.module_path)

    def run(self):
        ctx = self.ctx
        # User frames first, so their names are known when Apple frames,
        # messages and types that mention them are rewritten.
        for f in sorted(self.user, key=lambda f: f.index):
            self.frame(f)
        for f in self.system:   # learn user types mentioned (qualified) anywhere in Apple frames first
            self._rename_user_chains(f.function or "")
        for f in self.system:
            self.frame(f)
        ctx.main_executable = self.path(ctx.main_executable)

        stop = ctx.stop
        if stop.instrumentation_message:
            original = stop.instrumentation_message
            stop.instrumentation_message = self.message(original)
            stop.description = stop.description.replace(original, stop.instrumentation_message)
        if _MESSAGE_PREFIX.match(stop.description or ""):
            stop.description = self.message(stop.description, count=False)
        stop.description = self.other_text(stop.description)

        ctx.thread.name = self.label(ctx.thread.name)
        ctx.thread.queue = self.label(ctx.thread.queue)

        if ctx.exception is not None:
            exc = ctx.exception
            hints = [p for p, _ in NSEXCEPTION_HINTS]
            if not re.match(r"^(_?NS\w+|std::[\w:]+)$", exc.name or ""):
                exc.name = self.user_text(exc.name)
            exc.reason = self.message(exc.reason, patterns=hints)

        for key in ("fault_region", "pc_region", "stack_region"):
            region = getattr(ctx, key)
            if region is not None and region.image:
                region.image = self.path(region.image)

        if ctx.copied_value is not None:
            lay = ctx.copied_value
            lay.type, lay.variable = self.user_text(lay.type), self.user_text(lay.variable)
            for part in lay.parts:
                part.name, part.type = self.user_text(part.name), self.user_text(part.type)

        ctx.caller_prologue = [[op[0], self.other_text(op[1])] if len(op) > 1 else op for op in ctx.caller_prologue]
        return ctx


def anonymize(ctx, home=None):
    """A renamed deep copy of ctx, the report, and the original names (for
    `leftovers`). The input is not modified."""
    a = _Anonymizer(copy.deepcopy(ctx), home)
    out = a.run()
    return out, a.report, set(a.map)


def leftovers(text, originals):
    """Original names still present in text, as whole identifiers."""
    found = set(_IDENT.findall(text))
    return sorted(w for w in originals & found if len(w) > 2)
