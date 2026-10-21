from collections import OrderedDict

from fs_inspector.core.models import Field, Node, SourceRange
from fs_inspector.plugins.fat32_table import Fat32ChainReader


def short_name(data):
    raw = data[:11]
    if raw[0] == 0x05:
        raw = b"\xe5" + raw[1:]
    base = raw[:8].decode("cp437").rstrip()
    extension = raw[8:11].decode("cp437").rstrip()
    if data[12] & 0x08:
        base = base.lower()
    if data[12] & 0x10:
        extension = extension.lower()
    return base + ("." + extension if extension else "")


def name_checksum(name):
    value = 0
    for byte in name:
        value = (((value & 1) << 7) + (value >> 1) + byte) & 0xFF
    return value


def lfn_bytes(data):
    return data[1:11] + data[14:26] + data[28:32]


class Fat32DirectoryEntry:
    def __init__(self, data, offset, directory_cluster, index):
        self.data = data
        self.offset = offset
        self.directory_cluster = directory_cluster
        self.index = index
        self.attributes = data[11]
        self.first_cluster = int.from_bytes(data[20:22], "little") << 16 | int.from_bytes(data[26:28], "little")
        self.size = int.from_bytes(data[28:32], "little")
        self.end = data[0] == 0
        self.deleted = data[0] == 0xE5
        self.long_record = self.attributes == 0x0F
        self.volume_label = bool(self.attributes & 0x08)
        self.is_directory = bool(self.attributes & 0x10)
        self.short_name = short_name(data)
        self.name = self.short_name
        self.name_parts = ()
        self.diagnostics = []

    def expandable(self):
        return not (self.end or self.deleted or self.long_record or self.volume_label) and (self.is_directory or self.size > 0)

    def title(self):
        if self.end:
            return "End of directory"
        if self.deleted:
            return f"Deleted record at 0x{self.offset:X}"
        if self.long_record:
            return f"LFN record {self.data[0] & 0x1F}"
        if self.volume_label:
            return "Volume label: " + self.data[:11].decode("cp437").rstrip()
        return self.name

    def node(self, source_id, ref):
        raw_range = (SourceRange(source_id, self.offset, 32),)
        if self.end:
            return Node(ref, self.title(), "directory_end", (Field("Marker", "00", ranges=(SourceRange(source_id, self.offset, 1),)),), raw_range)
        if self.long_record:
            fields = []
            for name, value, relative, size in (
                ("Sequence", self.data[0], 0, 1),
                ("Attributes", "0x0F (long name)", 11, 1),
                ("Type", self.data[12], 12, 1),
                ("Short-name checksum", self.data[13], 13, 1),
                ("First cluster", int.from_bytes(self.data[26:28], "little"), 26, 2),
            ):
                fields.append(Field(name, value, ranges=(SourceRange(source_id, self.offset + relative, size),)))
            parts = tuple(SourceRange(source_id, self.offset + relative, size) for relative, size in ((1, 10), (14, 12), (28, 4)))
            fields.append(Field("UTF-16 name fragment", lfn_bytes(self.data).decode("utf-16-le", errors="replace"), ranges=parts))
            return Node(ref, self.title(), "lfn", tuple(fields), raw_range)
        name_ranges = tuple(SourceRange(source_id, offset + relative, size) for offset in self.name_parts for relative, size in ((1, 10), (14, 12), (28, 4)))
        fields = [
            Field("Name", self.name, ranges=name_ranges or (SourceRange(source_id, self.offset, 11),)),
            Field("Short name (CP437)", self.short_name, ranges=(SourceRange(source_id, self.offset, 11),)),
            Field("Attributes", f"0x{self.attributes:02X}", ranges=(SourceRange(source_id, self.offset + 11, 1),)),
            Field("First cluster", self.first_cluster, ranges=(SourceRange(source_id, self.offset + 20, 2), SourceRange(source_id, self.offset + 26, 2))),
            Field("File size", self.size, ranges=(SourceRange(source_id, self.offset + 28, 4),)),
        ]
        for name, relative in (("Creation time (raw)", 14), ("Creation date (raw)", 16), ("Access date (raw)", 18), ("Modification time (raw)", 22), ("Modification date (raw)", 24)):
            fields.append(Field(name, int.from_bytes(self.data[relative:relative + 2], "little"), ranges=(SourceRange(source_id, self.offset + relative, 2),)))
        diagnostics = list(self.diagnostics)
        if self.deleted:
            diagnostics.append("Deleted directory slot; its former data chain is not followed")
        if not self.is_directory and not self.volume_label and not self.size and self.first_cluster:
            diagnostics.append("An empty file has a nonzero first cluster")
        return Node(ref, self.title(), "directory_entry", tuple(fields), raw_range, tuple(diagnostics))


class Fat32DirectoryReader:
    def __init__(self, sources, source_id, layout, table, first_cluster):
        self.sources = sources
        self.source_id = source_id
        self.layout = layout
        self.chain = Fat32ChainReader(table, first_cluster)
        self.first_cluster = first_cluster
        self.buffers = OrderedDict()

    def raw_entry(self, index):
        if not isinstance(index, int) or not 0 <= index < 1048576:
            raise ValueError("Directory inspection is limited to 1048576 records")
        cluster_index, relative = divmod(index * 32, self.layout.cluster_size)
        cluster = self.chain.cluster_at(cluster_index)
        if cluster is None:
            return None
        offset = self.layout.cluster_offset(cluster)
        if cluster not in self.buffers:
            self.buffers[cluster] = self.sources.read_at(self.source_id, offset, self.layout.cluster_size)
            if len(self.buffers) > 8:
                self.buffers.popitem(last=False)
        self.buffers.move_to_end(cluster)
        return Fat32DirectoryEntry(self.buffers[cluster][relative:relative + 32], offset + relative, self.first_cluster, index)

    def entry_at(self, index):
        entry = self.raw_entry(index)
        if entry is None:
            return None
        if entry.end or entry.deleted or entry.long_record or entry.volume_label:
            return entry
        parts = []
        expected = 1
        checksum = name_checksum(entry.data[:11])
        for previous in range(index - 1, max(-1, index - 21), -1):
            record = self.raw_entry(previous)
            if record.deleted or not record.long_record:
                break
            data = record.data
            ordinal = data[0]
            if ordinal not in (expected, expected | 0x40) or data[12] or data[26:28] != b"\0\0" or data[13] != checksum:
                entry.diagnostics.append("Invalid LFN sequence or checksum; the short name is in use")
                return entry
            parts.append(record)
            if ordinal & 0x40:
                encoded = b"".join(lfn_bytes(part.data) for part in parts)
                units = [encoded[pos:pos + 2] for pos in range(0, len(encoded), 2)]
                if b"\0\0" in units:
                    end = units.index(b"\0\0")
                    if any(unit != b"\xff\xff" for unit in units[end + 1:]):
                        entry.diagnostics.append("Invalid LFN padding; the short name is in use")
                        return entry
                    encoded = encoded[:end * 2]
                try:
                    name = encoded.decode("utf-16-le")
                except UnicodeDecodeError:
                    name = ""
                if not name or len(encoded) > 510 or "\uffff" in name or any(char in name for char in ("/", "\\", "\0")):
                    entry.diagnostics.append("Invalid UTF-16 long name; the short name is in use")
                    return entry
                entry.name = name
                entry.name_parts = tuple(part.offset for part in parts)
                return entry
            expected += 1
        if parts:
            entry.diagnostics.append("Incomplete LFN sequence; the short name is in use")
        return entry
