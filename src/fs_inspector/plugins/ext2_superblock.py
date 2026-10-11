from collections import namedtuple
from uuid import UUID

from fs_inspector.core.models import Field, Node, SourceRange


SUPERBLOCK_OFFSET = 1024
SUPERBLOCK_SIZE = 1024
EXT2_MAGIC = 0xEF53
FILETYPE_FEATURE = 0x0002


class Ext2Superblock(namedtuple("Ext2Superblock", "inode_count block_count first_data_block log_block_size blocks_per_group inodes_per_group magic revision inode_size feature_compat feature_incompat feature_ro_compat uuid volume_name")):
    __slots__ = ()

    def block_size(self):
        if self.log_block_size != 0:
            raise ValueError("unsupported block-size exponent")
        return 1024


def magic_matches(data):
    return len(data) >= 0x3A and int.from_bytes(data[0x38:0x3A], "little") == EXT2_MAGIC


def decode_superblock(data):
    if len(data) != SUPERBLOCK_SIZE:
        raise ValueError(f"superblock must be {SUPERBLOCK_SIZE} bytes")

    def u16(offset):
        return int.from_bytes(data[offset : offset + 2], "little")

    def u32(offset):
        return int.from_bytes(data[offset : offset + 4], "little")

    return Ext2Superblock(
        inode_count=u32(0x00),
        block_count=u32(0x04),
        first_data_block=u32(0x14),
        log_block_size=u32(0x18),
        blocks_per_group=u32(0x20),
        inodes_per_group=u32(0x28),
        magic=u16(0x38),
        revision=u32(0x4C),
        inode_size=u16(0x58),
        feature_compat=u32(0x5C),
        feature_incompat=u32(0x60),
        feature_ro_compat=u32(0x64),
        uuid=str(UUID(bytes=data[0x68:0x78])),
        volume_name=data[0x78:0x88].split(b"\0", 1)[0],
    )


def support_problem(superblock, image_size):
    if superblock.magic != EXT2_MAGIC:
        return "Not an ext2 image: primary superblock magic is absent"
    if superblock.revision != 1:
        return f"Unsupported ext2 revision {superblock.revision}; this prototype supports revision 1"
    if (
        superblock.feature_compat != 0
        or superblock.feature_incompat != FILETYPE_FEATURE
        or superblock.feature_ro_compat != 0
    ):
        return (
            "Unsupported ext2 feature flags: "
            f"compat=0x{superblock.feature_compat:08X}, "
            f"incompat=0x{superblock.feature_incompat:08X}, "
            f"ro_compat=0x{superblock.feature_ro_compat:08X}; "
            "only the filetype incompat flag is supported"
        )
    if superblock.log_block_size != 0:
        return (
            f"Unsupported ext2 block-size exponent {superblock.log_block_size}; "
            "this prototype supports 1 KiB blocks"
        )
    if superblock.inode_size != 128:
        return (
            f"Unsupported ext2 inode size {superblock.inode_size}; "
            "this prototype supports 128-byte inodes"
        )
    if superblock.first_data_block != 1:
        return "Malformed ext2 superblock: first data block must be 1 for 1 KiB blocks"
    if superblock.inode_count == 0 or superblock.block_count <= 1:
        return "Malformed ext2 superblock: inode or block count is zero"
    if not 0 < superblock.blocks_per_group <= 8192:
        return "Malformed ext2 superblock: blocks per group exceed a 1 KiB bitmap"
    if not 0 < superblock.inodes_per_group <= 8192:
        return "Malformed ext2 superblock: inodes per group exceed a 1 KiB bitmap"
    declared_size = superblock.block_count * superblock.block_size()
    if declared_size > image_size:
        return (
            f"Truncated ext2 image: superblock declares {declared_size} bytes, "
            f"source contains {image_size}"
        )
    return None


def superblock_node(superblock, source_id, ref):
    def field(
        name, value, offset, length, description
    ):
        return Field(
            name,
            value,
            description,
            (SourceRange(source_id, SUPERBLOCK_OFFSET + offset, length),),
        )

    fields = (
        field("inode_count", superblock.inode_count, 0x00, 4, "Total inodes"),
        field("block_count", superblock.block_count, 0x04, 4, "Total blocks"),
        field("first_data_block", superblock.first_data_block, 0x14, 4, "First data block"),
        field("block_size", superblock.block_size(), 0x18, 4, "Bytes per block: 1024 shifted by the stored exponent"),
        field("blocks_per_group", superblock.blocks_per_group, 0x20, 4, "Blocks per group"),
        field("inodes_per_group", superblock.inodes_per_group, 0x28, 4, "Inodes per group"),
        field("magic", f"0x{superblock.magic:04X}", 0x38, 2, "ext2 signature"),
        field("revision", superblock.revision, 0x4C, 4, "Filesystem revision"),
        field("inode_size", superblock.inode_size, 0x58, 2, "Bytes per inode"),
        field("feature_compat", superblock.feature_compat, 0x5C, 4, "Compatible feature bits"),
        field("feature_incompat", superblock.feature_incompat, 0x60, 4, "Incompatible feature bits; 0x2 means filetype"),
        field("feature_ro_compat", superblock.feature_ro_compat, 0x64, 4, "Read-only-compatible feature bits"),
        field("uuid", superblock.uuid, 0x68, 16, "Filesystem UUID"),
        field("volume_name", superblock.volume_name, 0x78, 16, "Raw volume-label bytes; encoding unspecified"),
    )
    return Node(
        ref,
        "ext2 primary superblock",
        "ext2.superblock",
        fields,
        (SourceRange(source_id, SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE),),
    )
