from collections import namedtuple

from fs_inspector.core.models import Field, Node, SourceRange


DIRECT_BLOCKS = 12


class Ext2FileBlock(namedtuple("Ext2FileBlock", "logical_index logical_offset length physical_block pointer_range indirect_block indirect_pointer_range", defaults=[None, None])):
    __slots__ = ()


class Ext2FileBlockReader:
    def __init__(
        self,
        sources,
        source_id,
        superblock,
        inode,
        inode_offset,
    ):
        if inode.file_type() != "regular file":
            raise ValueError("inode is not a regular file")
        if inode.flags != 0:
            raise ValueError(f"unsupported regular-file inode flags: 0x{inode.flags:08X}")
        self._sources = sources
        self._source_id = source_id
        self._superblock = superblock
        self._inode = inode
        self._inode_offset = inode_offset
        self._block_size = superblock.block_size()
        self.block_count = (inode.size() + self._block_size - 1) // self._block_size
        if self.block_count > DIRECT_BLOCKS + self._block_size // 4:
            raise ValueError("regular file requires unsupported double-indirect blocks")

    def resolve(self, logical_index):
        if (
            isinstance(logical_index, bool)
            or not isinstance(logical_index, int)
            or not 0 <= logical_index < self.block_count
        ):
            raise ValueError("file block index is outside the file")

        logical_offset = logical_index * self._block_size
        length = min(self._block_size, self._inode.size() - logical_offset)
        pointers = self._inode.block_pointers()
        if logical_index < DIRECT_BLOCKS:
            physical = pointers[logical_index]
            pointer_range = SourceRange(
                self._source_id, self._inode_offset + 0x28 + logical_index * 4, 4
            )
            indirect = None
            indirect_pointer_range = None
        else:
            indirect = pointers[DIRECT_BLOCKS]
            indirect_pointer_range = SourceRange(
                self._source_id, self._inode_offset + 0x28 + DIRECT_BLOCKS * 4, 4
            )
            if indirect:
                self._check_block(indirect, "single-indirect pointer block")
                pointer_range = SourceRange(
                    self._source_id,
                    indirect * self._block_size + (logical_index - DIRECT_BLOCKS) * 4,
                    4,
                )
                physical = int.from_bytes(
                    self._sources.read_at(self._source_id, pointer_range.offset, 4), "little"
                )
            else:

                pointer_range = indirect_pointer_range
                physical = 0

        if physical:
            self._check_block(physical, "regular-file data block")
        return Ext2FileBlock(
            logical_index,
            logical_offset,
            length,
            physical or None,
            pointer_range,
            indirect or None,
            indirect_pointer_range,
        )

    def _check_block(self, number, label):
        if not 1 <= number < self._superblock.block_count:
            raise ValueError(f"{label} {number} lies outside the filesystem")
        if (number + 1) * self._block_size > self._sources.size_of(self._source_id):
            raise ValueError(f"{label} {number} lies outside the image")


def file_block_node(block, source_id, block_size, ref):
    fields = [
        Field("logical_block", block.logical_index, "Zero-based file block index"),
        Field("logical_offset", block.logical_offset, "Byte offset within the file"),
        Field("length", block.length, "File bytes in this block"),
    ]
    if block.indirect_pointer_range is not None:
        fields.append(
            Field(
                "single_indirect_block",
                block.indirect_block or 0,
                "Pointer block number; zero means the block is sparse",
                (block.indirect_pointer_range,),
            )
        )
    fields.append(
        Field(
            "physical_block",
            block.physical_block or 0,
            "Data block number; zero means no physical bytes",
            (block.pointer_range,),
        )
    )
    if block.physical_block is None:
        return Node(
            ref,
            f"File block {block.logical_index} (sparse)",
            "ext2.file_data_block",
            tuple(fields),
            diagnostics=("Sparse file block: logical bytes are zero; no source bytes exist",),
        )
    data_range = SourceRange(source_id, block.physical_block * block_size, block.length)
    return Node(
        ref,
        f"File block {block.logical_index}",
        "ext2.file_data_block",
        tuple(fields),
        (data_range,),
    )
