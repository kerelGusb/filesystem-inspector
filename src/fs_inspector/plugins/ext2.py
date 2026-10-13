from uuid import uuid4

from fs_inspector.core.models import Context, Link, NodeRef
from fs_inspector.core.plugin_api import (
    API_VERSION,
    FilesystemPlugin,
    FilesystemSession,
    LinkPage,
    PluginDescriptor,
    ProbeCandidate,
    ProbeResult,
)
from fs_inspector.plugins.ext2_directories import Ext2DirectoryReader, directory_entry_node
from fs_inspector.plugins.ext2_file_blocks import Ext2FileBlockReader, file_block_node
from fs_inspector.plugins.ext2_groups import (
    DESCRIPTOR_SIZE,
    decode_group_descriptor,
    descriptor_offset,
    group_count,
    group_descriptor_node,
    group_table_problem,
)
from fs_inspector.plugins.ext2_inodes import (
    INODE_SIZE,
    ROOT_INODE,
    decode_inode,
    inode_group_and_index,
    inode_node,
    inode_offset,
)
from fs_inspector.plugins.ext2_superblock import (
    SUPERBLOCK_OFFSET,
    SUPERBLOCK_SIZE,
    decode_superblock,
    magic_matches,
    superblock_node,
    support_problem,
)


CANDIDATE_ID = "primary"
CONTEXT_ID = "current"
SUPERBLOCK_KEY = "superblock"


class Ext2OpenError(ValueError):
    pass


class Ext2Plugin(FilesystemPlugin):
    descriptor = PluginDescriptor("ext2", "ext2", "0.1.0", API_VERSION)

    def probe(self, input_set, limits):
        if limits.max_read_bytes < SUPERBLOCK_SIZE:
            return ProbeResult(diagnostics=("Probe budget is too small for the ext2 superblock",))

        source_id = input_set.source_ids[0]
        source_size = input_set.size_of(source_id)
        if source_size < SUPERBLOCK_OFFSET + 0x3A:
            return ProbeResult(diagnostics=("Source is too short to contain an ext2 signature",))
        if source_size < SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE:
            try:
                magic = input_set.read_at(source_id, SUPERBLOCK_OFFSET + 0x38, 2)
            except (OSError, ValueError, EOFError) as exc:
                return ProbeResult(diagnostics=(f"Cannot read ext2 signature: {exc}",))
            if magic != b"\x53\xEF":
                return ProbeResult()
            return ProbeResult(
                (
                    ProbeCandidate(
                        CANDIDATE_ID,
                        "ext2 primary superblock",
                        "unsupported",
                        ("Truncated ext2 superblock: 1024 bytes at offset 1024 are required",),
                    ),
                )
            )

        try:
            data = input_set.read_at(source_id, SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE)
        except (OSError, ValueError, EOFError) as exc:
            return ProbeResult(diagnostics=(f"Cannot read ext2 superblock: {exc}",))
        if not magic_matches(data):
            return ProbeResult()

        superblock = decode_superblock(data)
        problem = support_problem(superblock, source_size)
        if problem is None:
            problem = group_table_problem(superblock, source_size)
        return ProbeResult(
            (
                ProbeCandidate(
                    CANDIDATE_ID,
                    "ext2 primary superblock",
                    "unsupported" if problem else "supported",
                    (problem,) if problem else (),
                ),
            )
        )

    def open(
        self,
        input_set,
        candidate_id,
        options,
    ):
        if candidate_id != CANDIDATE_ID:
            raise Ext2OpenError(f"Unknown ext2 candidate: {candidate_id!r}")
        if options:
            raise Ext2OpenError("ext2 opening options are not supported by this prototype")

        source_id = input_set.source_ids[0]
        source_size = input_set.size_of(source_id)
        if source_size < SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE:
            raise Ext2OpenError("Truncated ext2 superblock: 1024 bytes at offset 1024 are required")
        try:
            data = input_set.read_at(source_id, SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE)
        except (OSError, ValueError, EOFError) as exc:
            raise Ext2OpenError(f"Cannot read ext2 superblock: {exc}") from exc
        if not magic_matches(data):
            raise Ext2OpenError("Not an ext2 image: primary superblock magic is absent")
        superblock = decode_superblock(data)
        problem = support_problem(superblock, source_size)
        if problem is None:
            problem = group_table_problem(superblock, source_size)
        if problem:
            raise Ext2OpenError(problem)
        return Ext2Session(input_set, source_id, superblock)


class Ext2Session(FilesystemSession):
    def __init__(
        self, input_set, source_id, superblock
    ):
        self._input_set = input_set
        self._source_id = source_id
        self._superblock = superblock
        self._group_count = group_count(superblock)
        self._session_id = uuid4().hex
        self._root_ref = NodeRef(self._session_id, CONTEXT_ID, SUPERBLOCK_KEY)
        self._closed = False

    def contexts(self):
        self._ensure_open()
        return (Context(CONTEXT_ID, "Current image"),)

    def roots(self, context_id):
        self._ensure_open()
        if context_id != CONTEXT_ID:
            raise KeyError(context_id)
        return (self._root_ref,)

    def get_node(self, ref):
        self._ensure_open()
        if ref == self._root_ref:
            return superblock_node(self._superblock, self._source_id, self._root_ref)
        index = self._group_index(ref)
        if index is not None:
            descriptor = self._read_group_descriptor(index)
            offset = descriptor_offset(self._superblock, index)
            return group_descriptor_node(
                descriptor, self._superblock, self._source_id, offset, index, ref
            )
        number = self._inode_number(ref)
        if number is not None:
            inode, offset = self._read_inode(number)
            return inode_node(inode, number, self._source_id, offset, self._superblock.block_size(), ref)
        address = self._directory_entry_address(ref)
        if address is not None:
            parent_number, logical_offset = address
            entry = self._directory_reader(parent_number).entry_at(logical_offset)
            return directory_entry_node(entry, self._source_id, ref)
        address = self._file_block_address(ref)
        if address is not None:
            inode_number, logical_index = address
            block = self._file_block_reader(inode_number).resolve(logical_index)
            return file_block_node(block, self._source_id, self._superblock.block_size(), ref)
        raise KeyError(ref)

    def _read_inode(self, number):
        group_index, table_index = inode_group_and_index(self._superblock, number)
        descriptor = self._read_group_descriptor(group_index)
        offset = inode_offset(
            self._superblock,
            descriptor,
            group_index,
            table_index,
            self._input_set.size_of(self._source_id),
        )
        data = self._input_set.read_at(self._source_id, offset, INODE_SIZE)
        return decode_inode(data), offset

    def _directory_reader(self, number):
        inode, _ = self._read_inode(number)
        return Ext2DirectoryReader(self._input_set, self._source_id, self._superblock, inode)

    def _file_block_reader(self, number):
        inode, offset = self._read_inode(number)
        return Ext2FileBlockReader(self._input_set, self._source_id, self._superblock, inode, offset)

    def _read_group_descriptor(self, index):
        offset = descriptor_offset(self._superblock, index)
        data = self._input_set.read_at(self._source_id, offset, DESCRIPTOR_SIZE)
        return decode_group_descriptor(data)

    def list_links(self, ref, cursor, limit):
        self._ensure_open()
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("limit must be a positive integer")
        if ref == self._root_ref:
            if cursor is None:
                start = 0
            elif self._canonical_index(cursor):
                start = int(cursor)
            else:
                raise ValueError("Unknown ext2 link cursor")
            if start > self._group_count:
                raise ValueError("Unknown ext2 link cursor")
            end = min(start + min(limit, 128), self._group_count)
            links = tuple(
                Link(f"Block group {index}", "group_descriptor", self._group_ref(index))
                for index in range(start, end)
            )
            return LinkPage(links, str(end) if end < self._group_count else None)
        group_index = self._group_index(ref)
        if group_index is not None:
            if cursor is not None:
                raise ValueError("Unknown ext2 link cursor")
            if group_index == 0 and ROOT_INODE <= self._superblock.inode_count:
                return LinkPage((Link("Root inode (2)", "root_inode", self._inode_ref(ROOT_INODE)),))
            return LinkPage(())
        inode_number = self._inode_number(ref)
        if inode_number is not None:
            inode, inode_offset = self._read_inode(inode_number)
            if inode.file_type() == "regular file":
                reader = Ext2FileBlockReader(
                    self._input_set, self._source_id, self._superblock, inode, inode_offset
                )
                if cursor is None:
                    start = 0
                elif self._canonical_index(cursor):
                    start = int(cursor)
                else:
                    raise ValueError("Unknown ext2 link cursor")
                if start > reader.block_count:
                    raise ValueError("Unknown ext2 link cursor")
                end = min(start + min(limit, 128), reader.block_count)
                links = tuple(
                    Link(
                        f"File block {index}",
                        "file_data_block",
                        self._file_block_ref(inode_number, index),
                        target_has_links=False,
                    )
                    for index in range(start, end)
                )
                return LinkPage(links, str(end) if end < reader.block_count else None)
            if inode.file_type() != "directory":
                if cursor is not None:
                    raise ValueError("Unknown ext2 link cursor")
                return LinkPage(())
            reader = Ext2DirectoryReader(self._input_set, self._source_id, self._superblock, inode)
            if cursor is None:
                position = 0
            elif self._canonical_index(cursor):
                position = int(cursor)
            else:
                raise ValueError("Unknown ext2 link cursor")
            if position > reader.size():
                raise ValueError("Unknown ext2 link cursor")
            links = []
            while position < reader.size() and len(links) < min(limit, 128):
                entry = reader.entry_at(position, validate_boundary=not links)
                label = entry.display_name() if entry.inode_number else f"Unused record at 0x{position:X}"
                links.append(
                    Link(
                        label,
                        "directory_entry",
                        self._directory_entry_ref(inode_number, position),
                        target_has_links=False if entry.inode_number == 0 else None,
                    )
                )
                position += entry.record_length
            return LinkPage(tuple(links), str(position) if position < reader.size() else None)
        address = self._directory_entry_address(ref)
        if address is not None:
            if cursor is not None:
                raise ValueError("Unknown ext2 link cursor")
            parent_number, logical_offset = address
            entry = self._directory_reader(parent_number).entry_at(logical_offset)
            if entry.inode_number == 0:
                return LinkPage(())
            return LinkPage((Link(f"Inode {entry.inode_number}", "inode", self._inode_ref(entry.inode_number)),))
        address = self._file_block_address(ref)
        if address is not None:
            if cursor is not None:
                raise ValueError("Unknown ext2 link cursor")
            self._file_block_reader(address[0]).resolve(address[1])
            return LinkPage(())
        raise KeyError(ref)

    def _group_ref(self, index):
        return NodeRef(self._session_id, CONTEXT_ID, f"group:{index}")

    def _inode_ref(self, number):
        return NodeRef(self._session_id, CONTEXT_ID, f"inode:{number}")

    def _directory_entry_ref(self, parent_number, logical_offset):
        return NodeRef(self._session_id, CONTEXT_ID, f"dirent:{parent_number}:{logical_offset}")

    def _file_block_ref(self, inode_number, logical_index):
        return NodeRef(self._session_id, CONTEXT_ID, f"fileblock:{inode_number}:{logical_index}")

    def _group_index(self, ref):
        if ref.session_id != self._session_id or ref.context_id != CONTEXT_ID:
            return None
        prefix = "group:"
        if not ref.key.startswith(prefix):
            return None
        number = ref.key[len(prefix):]
        if not self._canonical_index(number):
            return None
        index = int(number)
        return index if index < self._group_count else None

    def _inode_number(self, ref):
        if ref.session_id != self._session_id or ref.context_id != CONTEXT_ID:
            return None
        prefix = "inode:"
        if not ref.key.startswith(prefix):
            return None
        number = ref.key[len(prefix):]
        if not self._canonical_index(number):
            return None
        value = int(number)
        return value if 1 <= value <= self._superblock.inode_count else None

    def _directory_entry_address(self, ref):
        if ref.session_id != self._session_id or ref.context_id != CONTEXT_ID:
            return None
        parts = ref.key.split(":")
        if len(parts) != 3 or parts[0] != "dirent":
            return None
        parent, offset = parts[1:]
        if not self._canonical_index(parent) or not self._canonical_index(offset):
            return None
        parent_number = int(parent)
        if not 1 <= parent_number <= self._superblock.inode_count:
            return None
        return parent_number, int(offset)

    def _file_block_address(self, ref):
        if ref.session_id != self._session_id or ref.context_id != CONTEXT_ID:
            return None
        parts = ref.key.split(":")
        if len(parts) != 3 or parts[0] != "fileblock":
            return None
        number, index = parts[1:]
        if not self._canonical_index(number) or not self._canonical_index(index):
            return None
        inode_number = int(number)
        if not 1 <= inode_number <= self._superblock.inode_count:
            return None
        return inode_number, int(index)

    def _canonical_index(self, value):
        return (
            value.isascii()
            and value.isdecimal()
            and len(value) <= 10
            and (value == "0" or not value.startswith("0"))
        )

    def close(self):
        self._closed = True

    def _ensure_open(self):
        if self._closed:
            raise RuntimeError("ext2 session is closed")
