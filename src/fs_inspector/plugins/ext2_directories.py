from collections import namedtuple

from fs_inspector.core.models import Field, Node, SourceRange


DIRECT_BLOCKS = 12
ENTRY_HEADER_SIZE = 8
DIRECTORY_TYPES = (
    "unknown",
    "regular file",
    "directory",
    "character device",
    "block device",
    "FIFO",
    "socket",
    "symbolic link",
)


class Ext2DirectoryEntry(namedtuple("Ext2DirectoryEntry", "inode_number record_length name file_type logical_offset source_offset")):
    __slots__ = ()

    def display_name(self):
        decoded = self.name.decode("utf-8", errors="backslashreplace")
        return "".join(character if character.isprintable() else ascii(character)[1:-1] for character in decoded)


class Ext2DirectoryReader:
    def __init__(
        self,
        sources,
        source_id,
        superblock,
        inode,
    ):
        if inode.file_type() != "directory":
            raise ValueError("inode is not a directory")
        if inode.flags != 0:
            raise ValueError(f"unsupported directory inode flags: 0x{inode.flags:08X}")
        max_blocks = DIRECT_BLOCKS + superblock.block_size() // 4
        if inode.size() > max_blocks * superblock.block_size():
            raise ValueError("directory requires unsupported double-indirect blocks")
        self._sources = sources
        self._source_id = source_id
        self._superblock = superblock
        self._inode = inode
        self._cached_index = None
        self._cached_data = b""
        self._cached_source_offset = 0

    def size(self):
        return self._inode.size()

    def entry_at(self, logical_offset, *, validate_boundary = True):
        if isinstance(logical_offset, bool) or not isinstance(logical_offset, int) or not 0 <= logical_offset < self.size():
            raise ValueError("directory entry offset is outside the directory")
        block_index, within_block = divmod(logical_offset, self._superblock.block_size())
        data, source_start = self._block(block_index)
        if validate_boundary:
            position = 0
            while position < within_block:
                earlier = self._decode(data, position, block_index, source_start)
                position += earlier.record_length
            if position != within_block:
                raise ValueError("directory entry offset is not a record boundary")
        return self._decode(data, within_block, block_index, source_start)

    def _block(self, logical_index):
        if self._cached_index == logical_index:
            return self._cached_data, self._cached_source_offset
        block_size = self._superblock.block_size()
        pointers = self._inode.block_pointers()
        if logical_index < DIRECT_BLOCKS:
            physical = pointers[logical_index]
        else:
            indirect = pointers[DIRECT_BLOCKS]
            self._check_block(indirect, "directory indirect pointer block")
            indirect_data = self._sources.read_at(self._source_id, indirect * block_size, block_size)
            index = logical_index - DIRECT_BLOCKS
            physical = int.from_bytes(indirect_data[index * 4 : index * 4 + 4], "little")
        self._check_block(physical, "directory data block")
        source_start = physical * block_size
        length = min(block_size, self.size() - logical_index * block_size)
        data = self._sources.read_at(self._source_id, source_start, length)
        self._cached_index = logical_index
        self._cached_data = data
        self._cached_source_offset = source_start
        return data, source_start

    def _check_block(self, number, label):
        if not 1 <= number < self._superblock.block_count:
            raise ValueError(f"{label} {number} lies outside the filesystem")
        block_end = (number + 1) * self._superblock.block_size()
        if block_end > self._sources.size_of(self._source_id):
            raise ValueError(f"{label} {number} lies outside the image")

    def _decode(
        self,
        data,
        within_block,
        block_index,
        source_start,
    ):
        logical_offset = block_index * self._superblock.block_size() + within_block
        if within_block + ENTRY_HEADER_SIZE > len(data):
            raise ValueError(f"truncated directory entry header at logical offset {logical_offset}")
        inode_number = int.from_bytes(data[within_block : within_block + 4], "little")
        record_length = int.from_bytes(data[within_block + 4 : within_block + 6], "little")
        name_length = data[within_block + 6]
        file_type = data[within_block + 7]
        if record_length < ENTRY_HEADER_SIZE or record_length % 4:
            raise ValueError(f"invalid directory record length {record_length} at logical offset {logical_offset}")
        if within_block + record_length > len(data):
            raise ValueError(f"directory record crosses block or file boundary at logical offset {logical_offset}")
        if name_length > record_length - ENTRY_HEADER_SIZE:
            raise ValueError(f"directory name exceeds record at logical offset {logical_offset}")
        if file_type >= len(DIRECTORY_TYPES):
            raise ValueError(f"invalid directory file type at logical offset {logical_offset}")
        if inode_number > self._superblock.inode_count or (inode_number and name_length == 0):
            raise ValueError(f"invalid directory inode or name at logical offset {logical_offset}")
        name_start = within_block + ENTRY_HEADER_SIZE
        name = data[name_start : name_start + name_length]
        if inode_number and (b"\0" in name or b"/" in name):
            raise ValueError(f"invalid directory name at logical offset {logical_offset}")
        return Ext2DirectoryEntry(
            inode_number,
            record_length,
            name,
            file_type,
            logical_offset,
            source_start + within_block,
        )


def directory_entry_node(entry, source_id, ref):
    offset = entry.source_offset

    def field(name, value, relative, length, description):
        return Field(name, value, description, (SourceRange(source_id, offset + relative, length),))

    title = f"Directory entry {entry.display_name()!r}" if entry.inode_number else "Unused directory record"
    return Node(
        ref,
        title,
        "ext2.directory_entry",
        (
            field("inode_number", entry.inode_number, 0, 4, "Referenced inode number; zero means unused"),
            field("record_length", entry.record_length, 4, 2, "On-disk record length"),
            field("name_length", len(entry.name), 6, 1, "Name length in bytes"),
            field("file_type", DIRECTORY_TYPES[entry.file_type], 7, 1, "Stored directory-entry type"),
            field("name", entry.name, 8, len(entry.name), "Raw name bytes; encoding is not assumed"),
        ),
        (SourceRange(source_id, offset, entry.record_length),),
    )
