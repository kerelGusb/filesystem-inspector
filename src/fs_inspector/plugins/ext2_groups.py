from collections import namedtuple

from fs_inspector.core.models import Field, Node, SourceRange


DESCRIPTOR_SIZE = 32


class Ext2GroupDescriptor(namedtuple("Ext2GroupDescriptor", "block_bitmap_block inode_bitmap_block inode_table_block free_blocks_count free_inodes_count used_dirs_count")):
    __slots__ = ()


def group_count(superblock):
    if superblock.blocks_per_group <= 0:
        raise ValueError("blocks_per_group must be positive")
    blocks = superblock.block_count - superblock.first_data_block
    if blocks <= 0:
        raise ValueError("no data blocks are declared")
    return (blocks + superblock.blocks_per_group - 1) // superblock.blocks_per_group


def descriptor_offset(superblock, index):
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < group_count(
        superblock
    ):
        raise ValueError("group index is outside the descriptor table")
    return (superblock.first_data_block + 1) * superblock.block_size() + index * DESCRIPTOR_SIZE


def group_table_problem(superblock, source_size):
    count = group_count(superblock)
    if superblock.inode_count > count * superblock.inodes_per_group:
        return "Malformed ext2 superblock: inode count exceeds block-group capacity"
    table_start = (superblock.first_data_block + 1) * superblock.block_size()
    table_end = table_start + count * DESCRIPTOR_SIZE
    if table_end > superblock.block_count * superblock.block_size() or table_end > source_size:
        return "Truncated ext2 group descriptor table"
    return None


def decode_group_descriptor(data):
    if len(data) != DESCRIPTOR_SIZE:
        raise ValueError(f"group descriptor must be {DESCRIPTOR_SIZE} bytes")

    def u16(offset):
        return int.from_bytes(data[offset : offset + 2], "little")

    def u32(offset):
        return int.from_bytes(data[offset : offset + 4], "little")

    return Ext2GroupDescriptor(
        block_bitmap_block=u32(0x00),
        inode_bitmap_block=u32(0x04),
        inode_table_block=u32(0x08),
        free_blocks_count=u16(0x0C),
        free_inodes_count=u16(0x0E),
        used_dirs_count=u16(0x10),
    )


def group_descriptor_node(
    descriptor,
    superblock,
    source_id,
    offset,
    index,
    ref,
):
    def field(name, value, relative, length, description):
        return Field(name, value, description, (SourceRange(source_id, offset + relative, length),))

    group_first = superblock.first_data_block + index * superblock.blocks_per_group
    group_end = min(group_first + superblock.blocks_per_group, superblock.block_count)
    table_blocks = (
        superblock.inodes_per_group * superblock.inode_size + superblock.block_size() - 1
    ) // superblock.block_size()
    diagnostics = []
    for name, block, length in (
        ("block bitmap", descriptor.block_bitmap_block, 1),
        ("inode bitmap", descriptor.inode_bitmap_block, 1),
        ("inode table", descriptor.inode_table_block, table_blocks),
    ):
        if block < group_first or block + length > group_end:
            diagnostics.append(
                f"Malformed block group {index}: {name} at block {block} "
                f"lies outside group blocks [{group_first}, {group_end})"
            )
    return Node(
        ref,
        f"Block group {index} descriptor",
        "ext2.group_descriptor",
        (
            field("block_bitmap_block", descriptor.block_bitmap_block, 0x00, 4, "Block bitmap location"),
            field("inode_bitmap_block", descriptor.inode_bitmap_block, 0x04, 4, "Inode bitmap location"),
            field("inode_table_block", descriptor.inode_table_block, 0x08, 4, "Start of inode table"),
            field("free_blocks_count", descriptor.free_blocks_count, 0x0C, 2, "Free blocks in group"),
            field("free_inodes_count", descriptor.free_inodes_count, 0x0E, 2, "Free inodes in group"),
            field("used_dirs_count", descriptor.used_dirs_count, 0x10, 2, "Directories in group"),
        ),
        (SourceRange(source_id, offset, DESCRIPTOR_SIZE),),
        tuple(diagnostics),
    )
