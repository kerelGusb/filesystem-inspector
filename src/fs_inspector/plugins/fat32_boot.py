from fs_inspector.core.models import Field, Node, SourceRange


BPB_FIELDS = (
    ("bytes_per_sector", 11, 2),
    ("sectors_per_cluster", 13, 1),
    ("reserved_sectors", 14, 2),
    ("fat_count", 16, 1),
    ("root_entry_count", 17, 2),
    ("total_sectors_16", 19, 2),
    ("media", 21, 1),
    ("fat_sectors_16", 22, 2),
    ("sectors_per_track", 24, 2),
    ("heads", 26, 2),
    ("hidden_sectors", 28, 4),
    ("total_sectors", 32, 4),
    ("fat_sectors", 36, 4),
    ("ext_flags", 40, 2),
    ("version", 42, 2),
    ("root_cluster", 44, 4),
    ("fsinfo_sector", 48, 2),
    ("backup_sector", 50, 2),
    ("drive_number", 64, 1),
    ("boot_signature", 66, 1),
    ("volume_id", 67, 4),
)


class Fat32BootSector:
    def __init__(self, data):
        if len(data) != 512:
            raise ValueError("A FAT boot sector requires 512 bytes")
        self.data = data
        for name, offset, size in BPB_FIELDS:
            setattr(self, name, int.from_bytes(data[offset:offset + size], "little"))
        self.volume_label = data[71:82].decode("cp437").rstrip()
        self.type_label = data[82:90].decode("cp437").rstrip()


class Fat32Layout:
    def __init__(self, boot, source_size):
        if boot.data[510:512] != b"\x55\xaa":
            raise ValueError("Missing FAT boot sector signature")
        if boot.bytes_per_sector != 512:
            raise ValueError("Only 512-byte FAT32 sectors are supported")
        if boot.sectors_per_cluster not in (1, 2, 4, 8, 16, 32, 64):
            raise ValueError("Unsupported FAT32 cluster size (expected 512 bytes to 32 KiB)")
        if not boot.reserved_sectors or boot.fat_count not in (1, 2):
            raise ValueError("Invalid reserved area or unsupported FAT count")
        if boot.root_entry_count or boot.fat_sectors_16 or boot.total_sectors_16:
            raise ValueError("FAT12 and FAT16 volumes are not supported")
        if not boot.fat_sectors or not boot.total_sectors:
            raise ValueError("FAT32 sector counts must be nonzero")
        self.boot = boot
        self.cluster_size = 512 * boot.sectors_per_cluster
        self.data_sector = boot.reserved_sectors + boot.fat_count * boot.fat_sectors
        self.cluster_count = (boot.total_sectors - self.data_sector) // boot.sectors_per_cluster
        if not 65525 <= self.cluster_count < 0x0FFFFFEE:
            raise ValueError("The data-cluster count does not describe a supported FAT32 volume")
        self.last_cluster = self.cluster_count + 1
        if boot.fat_sectors * 512 // 4 < self.cluster_count + 2:
            raise ValueError("FAT is too small for the declared data region")
        if boot.total_sectors * 512 > source_size:
            raise ValueError("Truncated FAT32 volume")
        if boot.version:
            raise ValueError("Only FAT32 version 0 is supported")
        if boot.ext_flags & ~0x008F:
            raise ValueError("Reserved FAT32 ExtFlags bits are set")
        self.mirrored = not bool(boot.ext_flags & 0x80)
        self.active_fat = 0 if self.mirrored else boot.ext_flags & 0x0F
        if self.active_fat >= boot.fat_count:
            raise ValueError("Active FAT index is outside the FAT copies")
        self.check_cluster(boot.root_cluster)
        for sector in (boot.fsinfo_sector, boot.backup_sector):
            if sector not in (0, 0xFFFF) and sector >= boot.reserved_sectors:
                raise ValueError("FSInfo or backup boot sector is outside the reserved area")

    def check_cluster(self, cluster):
        if not 2 <= cluster <= self.last_cluster:
            raise ValueError(f"Cluster {cluster} is outside the data region")

    def cluster_offset(self, cluster):
        self.check_cluster(cluster)
        return self.data_sector * 512 + (cluster - 2) * self.cluster_size

    def fat_offset(self, copy, cluster=0):
        if not 0 <= copy < self.boot.fat_count:
            raise ValueError("FAT copy is outside the volume")
        if not 0 <= cluster <= self.last_cluster:
            raise ValueError("FAT entry is outside the data-cluster table")
        return (self.boot.reserved_sectors + copy * self.boot.fat_sectors) * 512 + cluster * 4


def boot_node(boot, layout, source_id, ref, offset=0):
    fields = []
    for name, relative, size in BPB_FIELDS:
        fields.append(Field(name, getattr(boot, name), ranges=(SourceRange(source_id, offset + relative, size),)))
    fields.extend((
        Field("Volume label", boot.volume_label, ranges=(SourceRange(source_id, offset + 71, 11),)),
        Field("Type label", boot.type_label, "Informational only; format is determined from cluster count", (SourceRange(source_id, offset + 82, 8),)),
        Field("Cluster size", layout.cluster_size),
        Field("Data clusters", layout.cluster_count),
        Field("Data area offset", layout.data_sector * 512),
        Field("Active FAT", layout.active_fat),
        Field("FAT mirroring", layout.mirrored),
        Field("Signature", boot.data[510:512].hex(), ranges=(SourceRange(source_id, offset + 510, 2),)),
    ))
    diagnostics = []
    if offset and boot.data[11:90] != layout.boot.data[11:90]:
        diagnostics.append("Backup BPB differs from the primary BPB; the primary geometry is in use")
    if boot.data[510:512] != b"\x55\xaa":
        diagnostics.append("Invalid boot sector signature")
    return Node(ref, "FAT32 boot sector" if not offset else "Backup boot sector", "boot", tuple(fields), (SourceRange(source_id, offset, 512),), tuple(diagnostics))


class Fat32FsInfo:
    def __init__(self, data):
        self.lead_signature = int.from_bytes(data[0:4], "little")
        self.struct_signature = int.from_bytes(data[484:488], "little")
        self.free_count = int.from_bytes(data[488:492], "little")
        self.next_free = int.from_bytes(data[492:496], "little")
        self.trail_signature = int.from_bytes(data[508:512], "little")

    def node(self, layout, source_id, offset, ref):
        fields = []
        for name, relative in (("lead_signature", 0), ("struct_signature", 484), ("free_count", 488), ("next_free", 492), ("trail_signature", 508)):
            value = getattr(self, name)
            display = "Unknown" if name in ("free_count", "next_free") and value == 0xFFFFFFFF else value
            fields.append(Field(name, display, ranges=(SourceRange(source_id, offset + relative, 4),)))
        diagnostics = ["FSInfo counters are hints; allocation is read from the FAT"]
        if (self.lead_signature, self.struct_signature, self.trail_signature) != (0x41615252, 0x61417272, 0xAA550000):
            diagnostics.append("Invalid FSInfo signatures")
        if self.free_count != 0xFFFFFFFF and self.free_count > layout.cluster_count:
            diagnostics.append("Free-cluster count exceeds the data region")
        if self.next_free != 0xFFFFFFFF and not 2 <= self.next_free <= layout.last_cluster:
            diagnostics.append("Next-free hint is outside the data region")
        return Node(ref, "FSInfo", "fsinfo", tuple(fields), (SourceRange(source_id, offset, 512),), tuple(diagnostics))
