"""The cases of a Swift enum, read from the reflection metadata in its binary.

lldb's SBType has nothing on Swift enum cases (no fields, no members, size 0),
and an SBValue only shows the case it currently holds. The compiler also
writes a field descriptor for every enum into __TEXT.__swift5_fieldmd: one
record per case, with the case name and the payload's mangled type name. This
module reads those records. It reads the binary file through the module's
sections, and process memory only to follow a pointer to a type in another
image. It never runs code in the process.

Layouts (swift/include/swift/RemoteInspection/Records.h, ABI/Metadata.h):

    FieldDescriptor   i32 MangledTypeName, i32 Superclass, u16 Kind,
                      u16 FieldRecordSize, u32 NumFields, FieldRecord[...]
    FieldRecord       u32 Flags, i32 MangledTypeName, i32 FieldName
    ContextDescriptor u32 Flags, i32 Parent, then for modules and types
                      i32 Name (extensions: i32 ExtendedContext, a mangled name)

All i32 fields are offsets relative to their own address. In mangled names,
bytes 0x01 and 0x02 start a symbolic reference: a 4-byte relative offset to a
context descriptor (0x01) or to a pointer to one (0x02).
"""

import struct

import lldb

FIELD_DESCRIPTOR_SIZE = 16
ENUM_KINDS = (2, 3)            # Enum, MultiPayloadEnum
INDIRECT_CASE = 0x1            # FieldRecord flag: payload is boxed already
CONTEXT_MODULE, CONTEXT_EXTENSION = 0, 1
CONTEXT_TYPES = (16, 17, 18)   # class, struct, enum
MAX_NAME = 512
MAX_DEPTH = 12


class Case:
    def __init__(self, name, payload_types, indirect):
        self.name = name
        self.payload_types = payload_types   # qualified names of the payload's nominal types
        self.indirect = indirect


class _Image:
    """Reads one loaded image by load address, from its file when possible."""

    def __init__(self, target, module):
        self.target = target
        self.process = target.GetProcess()
        self.sections = []          # (load start, load end, SBSection), __TEXT only
        self.cache = {}
        text = module.FindSection("__TEXT")
        for i in range(text.GetNumSubSections() if text.IsValid() else 0):
            sub = text.GetSubSectionAtIndex(i)
            start = sub.GetLoadAddress(target)
            if start != lldb.LLDB_INVALID_ADDRESS and sub.GetByteSize():
                self.sections.append((start, start + sub.GetByteSize(), sub))

    def section(self, name):
        for start, end, sub in self.sections:
            if sub.GetName() == name:
                return start, end
        return None

    def read(self, address, size):
        for start, end, sub in self.sections:
            if start <= address and address + size <= end:
                data = self.cache.get(start)
                if data is None:
                    sb = sub.GetSectionData()
                    error = lldb.SBError()
                    data = bytes(sb.ReadRawData(error, 0, sb.GetByteSize()) or b"") if sb.GetByteSize() else b""
                    self.cache[start] = data
                offset = address - start
                if offset + size <= len(data):
                    return data[offset:offset + size]
        error = lldb.SBError()   # outside __TEXT, or not in the file: read the live process
        data = self.process.ReadMemory(address, size, error)
        if not error.Success() or data is None or len(data) < size:
            raise IOError("can't read 0x%x" % address)
        return bytes(data)

    def i32(self, address):
        return struct.unpack("<i", self.read(address, 4))[0]

    def u32(self, address):
        return struct.unpack("<I", self.read(address, 4))[0]

    def u16(self, address):
        return struct.unpack("<H", self.read(address, 2))[0]

    def relative(self, address):
        offset = self.i32(address)
        return address + offset if offset else 0

    def pointer(self, address):
        error = lldb.SBError()
        value = self.process.ReadPointerFromMemory(address, error)
        if not error.Success():
            raise IOError("can't read pointer at 0x%x" % address)
        fix = getattr(self.process, "FixAddress", None)   # strip pointer authentication bits
        return fix(value) if fix else value & 0x0000FFFFFFFFFFFF

    def cstring(self, address):
        out = b""
        while len(out) < MAX_NAME:
            chunk = self.read(address + len(out), 1)
            if chunk == b"\0":
                return out.decode("utf-8", "replace")
            out += chunk
        return out.decode("utf-8", "replace")

    def symbolic_references(self, address):
        """Context descriptors referenced from the mangled name at address."""
        refs = []
        while len(refs) < 64:
            byte = self.read(address, 1)[0]
            if byte == 0:
                break
            if byte in (1, 2):
                target = address + 1 + self.i32(address + 1)
                refs.append(target if byte == 1 else self.pointer(target))
                address += 5
            elif 3 <= byte <= 0x17:
                address += 5        # other 4-byte references (accessor functions...)
            elif 0x18 <= byte <= 0x1F:
                address += 9        # absolute 8-byte references
            else:
                address += 1
        return refs

    def context_name(self, descriptor, depth=0):
        """'Module.Outer.Inner' for a module, type or extension descriptor."""
        if not descriptor or depth > MAX_DEPTH:
            return None
        kind = self.u32(descriptor) & 0x1F
        if kind == CONTEXT_MODULE:
            return self.cstring(self.relative(descriptor + 8))
        if kind == CONTEXT_EXTENSION:
            refs = self.symbolic_references(self.relative(descriptor + 8))
            return self.context_name(refs[0], depth + 1) if refs else None
        if kind not in CONTEXT_TYPES:
            return None
        name = self.cstring(self.relative(descriptor + 8))
        parent_offset = self.i32(descriptor + 4)
        parent = None
        if parent_offset:
            parent = descriptor + 4 + (parent_offset & ~1)
            if parent_offset & 1:
                parent = self.pointer(parent)
        outer = self.context_name(parent, depth + 1) if parent else None
        return "%s.%s" % (outer, name) if outer else name

    def simple_name(self, descriptor):
        kind = self.u32(descriptor) & 0x1F
        return self.cstring(self.relative(descriptor + 8)) if kind in CONTEXT_TYPES else None


def enum_cases(target, module, qualified_name):
    """[Case] for the enum named `qualified_name` (e.g. 'App.ListItem.Trailing')
    if its field descriptor is in `module`, else None."""
    image = _Image(target, module)
    bounds = image.section("__swift5_fieldmd")
    if bounds is None:
        return None
    simple = qualified_name.rsplit(".", 1)[-1]
    address, end = bounds
    while address + FIELD_DESCRIPTOR_SIZE <= end:
        kind, record_size, count = image.u16(address + 8), image.u16(address + 10), image.u32(address + 12)
        next_address = address + FIELD_DESCRIPTOR_SIZE + count * record_size
        if kind in ENUM_KINDS and image.i32(address):
            refs = image.symbolic_references(image.relative(address))
            # Compare the cheap simple name before walking the parent chain.
            if refs and image.simple_name(refs[0]) == simple and image.context_name(refs[0]) == qualified_name:
                return _cases(image, address, record_size, count)
        if record_size < 12 or next_address <= address:
            return None   # not a layout we understand
        address = next_address
    return None


def _cases(image, descriptor, record_size, count):
    cases = []
    for i in range(count):
        record = descriptor + FIELD_DESCRIPTOR_SIZE + i * record_size
        flags = image.u32(record)
        name = image.cstring(image.relative(record + 8))
        payload = image.relative(record + 4)
        types = [image.context_name(ref) for ref in image.symbolic_references(payload)] if payload else []
        cases.append(Case(name, [t for t in types if t], bool(flags & INDIRECT_CASE)))
    return cases
