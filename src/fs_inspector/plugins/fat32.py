from collections import OrderedDict
from uuid import uuid4

from fs_inspector.core.models import Context, Field, Link, Node, NodeRef, SourceRange
from fs_inspector.core.plugin_api import API_VERSION, FilesystemPlugin, FilesystemSession, LinkPage, PluginDescriptor, ProbeCandidate, ProbeResult
from fs_inspector.plugins.fat32_boot import Fat32BootSector, Fat32FsInfo, Fat32Layout, boot_node
from fs_inspector.plugins.fat32_data import Fat32FileReader
from fs_inspector.plugins.fat32_directories import Fat32DirectoryReader
from fs_inspector.plugins.fat32_table import Fat32TableReader, entry_kind


class Fat32Plugin(FilesystemPlugin):
    descriptor = PluginDescriptor("fat32", "FAT32", "0.1.0", API_VERSION)

    def probe(self, input_set, limits):
        source_id = input_set.source_ids[0]
        if limits.max_read_bytes < 512 or input_set.size_of(source_id) < 512:
            return ProbeResult()
        try:
            data = input_set.read_at(source_id, 0, 512)
            if data[510:512] != b"\x55\xaa":
                return ProbeResult()
            boot = Fat32BootSector(data)
            Fat32Layout(boot, input_set.size_of(source_id))
        except (OSError, EOFError, ValueError) as exc:
            return ProbeResult((ProbeCandidate("volume", "FAT volume at offset 0", "unsupported", (str(exc),)),))
        return ProbeResult((ProbeCandidate("volume", "FAT32 volume at offset 0", "supported"),))

    def open(self, input_set, candidate_id, options):
        if candidate_id != "volume" or options:
            raise ValueError("Unknown FAT32 candidate or unsupported opening options")
        source_id = input_set.source_ids[0]
        boot = Fat32BootSector(input_set.read_at(source_id, 0, 512))
        layout = Fat32Layout(boot, input_set.size_of(source_id))
        return Fat32Session(input_set, source_id, layout)


class Fat32Session(FilesystemSession):
    def __init__(self, sources, source_id, layout):
        self.sources = sources
        self.source_id = source_id
        self.layout = layout
        self.boot = layout.boot
        self.session_id = uuid4().hex
        self.closed = False
        self.table = Fat32TableReader(sources, source_id, layout)
        self.directories = OrderedDict()
        self.files = OrderedDict()

    def contexts(self):
        self.ensure_open()
        return (Context("current", "Current volume"),)

    def roots(self, context_id):
        self.ensure_open()
        if context_id != "current":
            raise KeyError(context_id)
        return (self.ref("boot"),)

    def ref(self, key):
        return NodeRef(self.session_id, "current", key)

    def ensure_open(self):
        if self.closed:
            raise ValueError("FAT32 session is closed")

    def address(self, ref):
        self.ensure_open()
        if ref.session_id != self.session_id or ref.context_id != "current":
            raise KeyError("Foreign FAT32 node reference")
        parts = ref.key.split(":")
        if parts[0] not in ("boot", "backup", "fsinfo", "fat", "fatentry", "directory", "dirent", "filecluster", "cluster"):
            raise KeyError(ref.key)
        counts = {"boot": 0, "backup": 0, "fsinfo": 0, "fat": 1, "fatentry": 2, "directory": 1, "dirent": 2, "filecluster": 3, "cluster": 1}
        if len(parts) != counts[parts[0]] + 1:
            raise KeyError(ref.key)
        return parts[0], tuple(self.number(part) for part in parts[1:])

    def number(self, text):
        if not isinstance(text, str) or not text.isascii() or not text.isdecimal() or len(text) > 10 or str(int(text)) != text:
            raise ValueError("Invalid FAT32 address or page cursor")
        return int(text)

    def directory(self, cluster):
        self.layout.check_cluster(cluster)
        if cluster not in self.directories:
            self.directories[cluster] = Fat32DirectoryReader(self.sources, self.source_id, self.layout, self.table, cluster)
            if len(self.directories) > 32:
                self.directories.popitem(last=False)
        self.directories.move_to_end(cluster)
        return self.directories[cluster]

    def entry(self, cluster, index):
        entry = self.directory(cluster).entry_at(index)
        if entry is None:
            raise KeyError("Directory entry is outside its cluster chain")
        return entry

    def file(self, cluster, index):
        key = (cluster, index)
        if key not in self.files:
            entry = self.entry(cluster, index)
            if not entry.expandable() or entry.is_directory:
                raise ValueError("Directory record does not describe a nonempty file")
            self.files[key] = Fat32FileReader(self.layout, self.table, entry)
            if len(self.files) > 32:
                self.files.popitem(last=False)
        self.files.move_to_end(key)
        return self.files[key]

    def get_node(self, ref):
        kind, args = self.address(ref)
        if kind == "boot":
            return boot_node(self.boot, self.layout, self.source_id, ref)
        if kind == "backup":
            offset = self.reserved_offset(self.boot.backup_sector)
            boot = Fat32BootSector(self.sources.read_at(self.source_id, offset, 512))
            return boot_node(boot, self.layout, self.source_id, ref, offset)
        if kind == "fsinfo":
            offset = self.reserved_offset(self.boot.fsinfo_sector)
            info = Fat32FsInfo(self.sources.read_at(self.source_id, offset, 512))
            return info.node(self.layout, self.source_id, offset, ref)
        if kind == "fat":
            copy = args[0]
            offset = self.layout.fat_offset(copy)
            fields = (Field("Copy index", copy), Field("Active for chain traversal", copy == self.layout.active_fat), Field("FAT entries for this volume", self.layout.cluster_count + 2))
            return Node(ref, f"FAT copy {copy}", "fat", fields, (SourceRange(self.source_id, offset, self.boot.fat_sectors * 512),))
        if kind == "fatentry":
            copy, cluster = args
            offset = self.layout.fat_offset(copy, cluster)
            raw = self.table.raw_entry(copy, cluster)
            value = raw & 0x0FFFFFFF
            label = "Reserved FAT entry" if cluster < 2 else entry_kind(value)
            fields = (Field("Entry index", cluster), Field("Raw 32-bit value", f"0x{raw:08X}", ranges=(SourceRange(self.source_id, offset, 4),)), Field("Lower 28 bits", f"0x{value:07X}"), Field("Meaning", label))
            diagnostics = []
            if self.layout.mirrored and any((self.table.raw_entry(other, cluster) & 0x0FFFFFFF) != value for other in range(self.boot.fat_count)):
                diagnostics.append("Mirrored FAT copies disagree for this entry; traversal uses FAT 0")
            if cluster >= 2 and entry_kind(value) == "next cluster" and not 2 <= value <= self.layout.last_cluster:
                diagnostics.append("Next-cluster pointer is outside the volume")
            return Node(ref, f"FAT {copy} entry {cluster}", "fat_entry", fields, (SourceRange(self.source_id, offset, 4),), tuple(diagnostics))
        if kind == "directory":
            cluster = args[0]
            offset = self.layout.cluster_offset(cluster)
            fields = (Field("First cluster", cluster), Field("Cluster size", self.layout.cluster_size), Field("FAT used", self.layout.active_fat))
            return Node(ref, "Root directory" if cluster == self.boot.root_cluster else f"Directory at cluster {cluster}", "directory", fields, (SourceRange(self.source_id, offset, self.layout.cluster_size),))
        if kind == "dirent":
            return self.entry(*args).node(self.source_id, ref)
        if kind == "filecluster":
            return self.file(*args[:2]).resolve(args[2]).node(self.source_id, ref)
        cluster = args[0]
        offset = self.layout.cluster_offset(cluster)
        span = SourceRange(self.source_id, offset, self.layout.cluster_size)
        return Node(ref, f"Raw cluster {cluster}", "cluster", (Field("Physical cluster", cluster), Field("Bytes", self.layout.cluster_size, ranges=(span,))), (span,))

    def reserved_offset(self, sector):
        if sector in (0, 0xFFFF) or sector >= self.boot.reserved_sectors:
            raise KeyError("Optional reserved-sector structure is absent")
        return sector * 512

    def list_links(self, ref, cursor, limit):
        kind, args = self.address(ref)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 128:
            raise ValueError("FAT32 link page size must be between 1 and 128")
        start = 0 if cursor is None else self.number(cursor)
        if kind == "fat":
            copy = args[0]
            self.layout.fat_offset(copy)
            total = self.layout.cluster_count + 2
            links = []
            for cluster in range(start, min(total, start + limit)):
                value = self.table.raw_entry(copy, cluster) & 0x0FFFFFFF
                expandable = cluster >= 2 and entry_kind(value) in ("next cluster", "end of chain")
                links.append(Link(f"Entry {cluster}: {entry_kind(value) if cluster >= 2 else 'reserved'}", "entry", self.ref(f"fatentry:{copy}:{cluster}"), expandable))
            return LinkPage(tuple(links), str(start + limit) if start + limit < total else None)
        if kind == "directory":
            reader = self.directory(args[0])
            links = []
            for index in range(start, start + limit):
                entry = reader.entry_at(index)
                if entry is None:
                    return LinkPage(tuple(links))
                links.append(Link(entry.title(), "entry", self.ref(f"dirent:{args[0]}:{index}"), entry.expandable()))
                if entry.end:
                    return LinkPage(tuple(links))
            return LinkPage(tuple(links), str(start + limit))
        if kind == "dirent":
            entry = self.entry(*args)
            if entry.expandable() and not entry.is_directory:
                file = self.file(*args)
                links = []
                for index in range(start, min(file.cluster_count, start + limit)):
                    block = file.resolve(index)
                    links.append(Link(f"Cluster {index} (physical {block.cluster}, {block.length} bytes)", "data", self.ref(f"filecluster:{args[0]}:{args[1]}:{index}"), False))
                return LinkPage(tuple(links), str(start + limit) if start + limit < file.cluster_count else None)
        links = self.fixed_links(ref, kind, args)
        return LinkPage(tuple(links[start:start + limit]), str(start + limit) if start + limit < len(links) else None)

    def fixed_links(self, ref, kind, args):
        if kind == "boot":
            links = []
            if self.boot.fsinfo_sector not in (0, 0xFFFF):
                links.append(Link("FSInfo", "metadata", self.ref("fsinfo"), False))
            if self.boot.backup_sector not in (0, 0xFFFF):
                links.append(Link("Backup boot sector", "backup", self.ref("backup"), False))
            for copy in range(self.boot.fat_count):
                suffix = " (active)" if copy == self.layout.active_fat else ""
                links.append(Link(f"FAT copy {copy}{suffix}", "allocation", self.ref(f"fat:{copy}"), True))
            links.append(Link("Root directory", "directory", self.ref(f"directory:{self.boot.root_cluster}"), True))
            return links
        if kind == "dirent":
            entry = self.entry(*args)
            if entry.expandable() and entry.is_directory:
                cluster = entry.first_cluster
                if cluster == 0 and entry.short_name == "..":
                    cluster = self.boot.root_cluster
                self.layout.check_cluster(cluster)
                return [Link("Directory contents", "directory", self.ref(f"directory:{cluster}"), True)]
            return []
        if kind == "fatentry":
            copy, cluster = args
            self.layout.fat_offset(copy, cluster)
            value = self.table.raw_entry(copy, cluster) & 0x0FFFFFFF
            if cluster < 2 or entry_kind(value) not in ("next cluster", "end of chain"):
                return []
            links = [Link(f"Raw cluster {cluster}", "data", self.ref(f"cluster:{cluster}"), False)]
            if entry_kind(value) == "next cluster" and 2 <= value <= self.layout.last_cluster:
                next_value = self.table.raw_entry(copy, value) & 0x0FFFFFFF
                expandable = entry_kind(next_value) in ("next cluster", "end of chain")
                links.append(Link(f"Next FAT entry: {value}", "next", self.ref(f"fatentry:{copy}:{value}"), expandable))
            return links
        self.get_node(ref)
        return []

    def close(self):
        self.closed = True
        self.directories.clear()
        self.files.clear()
        self.table.sectors.clear()
