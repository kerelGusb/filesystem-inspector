from collections import namedtuple

from fs_inspector.core.models import Field, Node, SourceRange
from fs_inspector.plugins.ext2_groups import group_count


INODE_SIZE = 128
ROOT_INODE = 2
FILE_TYPES = {
    0x1000: "FIFO",
    0x2000: "character device",
    0x4000: "directory",
    0x6000: "block device",
    0x8000: "regular file",
    0xA000: "symbolic link",
    0xC000: "socket",
}


class Ext2Inode(namedtuple("Ext2Inode", "mode uid_low size_low access_time change_time modification_time deletion_time gid_low link_count allocated_sectors_512 flags block_map generation file_acl_block size_high_or_directory_acl")):
    __slots__ = ()

    def file_type(self):
        return FILE_TYPES.get(self.mode & 0xF000, "unknown")

    def size(self):
        if self.file_type() == "regular file":
            return self.size_low | (self.size_high_or_directory_acl << 32)
        return self.size_low

    def block_pointers(self):
        return tuple(
            int.from_bytes(self.block_map[index : index + 4], "little")
            for index in range(0, len(self.block_map), 4)
        )


def inode_group_and_index(superblock, number):
    if isinstance(number, bool) or not isinstance(number, int) or not 1 <= number <= superblock.inode_count:
        raise ValueError("inode number is outside the filesystem")
    if superblock.inodes_per_group <= 0:
        raise ValueError("inodes_per_group must be positive")
    group_index, table_index = divmod(number - 1, superblock.inodes_per_group)
    if group_index >= group_count(superblock):
        raise ValueError("inode number has no block group")
    return group_index, table_index


def inode_offset(
    superblock,
    descriptor,
    group_index,
    table_index,
    source_size,
):
    if not 0 <= group_index < group_count(superblock):
        raise ValueError("inode block group is outside the filesystem")
    if not 0 <= table_index < superblock.inodes_per_group:
        raise ValueError("inode table index is outside the block group")
    table_blocks = (
        superblock.inodes_per_group * superblock.inode_size + superblock.block_size() - 1
    ) // superblock.block_size()
    group_first = superblock.first_data_block + group_index * superblock.blocks_per_group
    group_end = min(group_first + superblock.blocks_per_group, superblock.block_count)
    table_first = descriptor.inode_table_block
    if table_first < group_first or table_first + table_blocks > group_end:
        raise ValueError(f"inode table for block group {group_index} lies outside that group")
    offset = table_first * superblock.block_size() + table_index * superblock.inode_size
    if offset + superblock.inode_size > min(source_size, superblock.block_count * superblock.block_size()):
        raise ValueError("inode record lies outside the image")
    return offset


def decode_inode(data):
    if len(data) != INODE_SIZE:
        raise ValueError(f"inode record must be {INODE_SIZE} bytes")

    def u16(offset):
        return int.from_bytes(data[offset : offset + 2], "little")

    def u32(offset):
        return int.from_bytes(data[offset : offset + 4], "little")

    return Ext2Inode(
        mode=u16(0x00),
        uid_low=u16(0x02),
        size_low=u32(0x04),
        access_time=u32(0x08),
        change_time=u32(0x0C),
        modification_time=u32(0x10),
        deletion_time=u32(0x14),
        gid_low=u16(0x18),
        link_count=u16(0x1A),
        allocated_sectors_512=u32(0x1C),
        flags=u32(0x20),
        block_map=data[0x28:0x64],
        generation=u32(0x64),
        file_acl_block=u32(0x68),
        size_high_or_directory_acl=u32(0x6C),
    )


def inode_node(
    inode, number, source_id, offset, block_size, ref
):
    def spans(*parts):
        return tuple(SourceRange(source_id, offset + relative, length) for relative, length in parts)

    def field(
        name,
        value,
        description,
        *parts,
    ):
        return Field(name, value, description, spans(*parts))

    size_parts = ((0x04, 4), (0x6C, 4)) if inode.file_type() == "regular file" else ((0x04, 4),)
    fields = [
        field("mode", oct(inode.mode), "Unix type and permission bits", (0x00, 2)),
        field("file_type", inode.file_type(), "Derived from mode bits", (0x00, 2)),
        field("uid_low", inode.uid_low, "Low 16 bits of owner UID", (0x02, 2)),
        field("gid_low", inode.gid_low, "Low 16 bits of owner GID", (0x18, 2)),
        field("size", inode.size(), "Logical size in bytes", *size_parts),
        field("access_time", inode.access_time, "Unix seconds", (0x08, 4)),
        field("change_time", inode.change_time, "Unix seconds", (0x0C, 4)),
        field("modification_time", inode.modification_time, "Unix seconds", (0x10, 4)),
        field("deletion_time", inode.deletion_time, "Unix seconds", (0x14, 4)),
        field("link_count", inode.link_count, "Hard-link count", (0x1A, 2)),
        field("allocated_sectors_512", inode.allocated_sectors_512, "Allocated 512-byte sectors", (0x1C, 4)),
        field("flags", f"0x{inode.flags:08X}", "Inode flags", (0x20, 4)),
        field("generation", inode.generation, "NFS generation", (0x64, 4)),
        field("file_acl_block", inode.file_acl_block, "Extended-attribute block", (0x68, 4)),
    ]
    if inode.file_type() == "directory":
        fields.append(
            field("directory_acl_block", inode.size_high_or_directory_acl, "Directory ACL block", (0x6C, 4))
        )
    if inode.file_type() in ("directory", "regular file") and inode.flags == 0:
        labels = tuple(f"direct_block_{i}" for i in range(12)) + (
            "single_indirect_block",
            "double_indirect_block",
            "triple_indirect_block",
        )
        descriptions = ("Direct data block number",) * 12 + (
            "Single-indirect pointer block number",
            "Double-indirect pointer block number",
            "Triple-indirect pointer block number",
        )
        fields.extend(
            field(label, pointer, descriptions[i], (0x28 + 4 * i, 4))
            for i, (label, pointer) in enumerate(zip(labels, inode.block_pointers()))
        )
    else:
        fields.append(
            field("block_map_raw", inode.block_map, "Type-dependent inode data", (0x28, 60))
        )
    diagnostics = []
    if inode.file_type() in ("directory", "regular file"):
        if inode.flags != 0:
            diagnostics.append(
                f"Unsupported {inode.file_type()} inode flags 0x{inode.flags:08X}; "
                "block-map navigation is unavailable"
            )
        max_single_indirect_bytes = (12 + block_size // 4) * block_size
        if inode.size() > max_single_indirect_bytes:
            diagnostics.append(
                f"Unsupported {inode.file_type()} size {inode.size()}: "
                "double-indirect or larger block mapping is required"
            )
    return Node(
        ref,
        f"Inode {number} ({inode.file_type()})",
        "ext2.inode",
        tuple(fields),
        (SourceRange(source_id, offset, INODE_SIZE),),
        tuple(diagnostics),
    )
