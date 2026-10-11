from uuid import uuid4

from fs_inspector.core.models import Context, NodeRef
from fs_inspector.core.plugin_api import API_VERSION, LinkPage, PluginDescriptor, ProbeCandidate, ProbeResult
from fs_inspector.plugins.ext2_superblock import SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE, decode_superblock, magic_matches, superblock_node, support_problem


class Ext2Plugin:
    descriptor = PluginDescriptor("ext2", "ext2", "0.1.0", API_VERSION)

    def probe(self, input_set, limits):
        source_id = input_set.source_ids[0]
        if limits.max_read_bytes < SUPERBLOCK_SIZE or input_set.size_of(source_id) < SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE:
            return ProbeResult()
        data = input_set.read_at(source_id, SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE)
        if not magic_matches(data):
            return ProbeResult()
        problem = support_problem(decode_superblock(data), input_set.size_of(source_id))
        return ProbeResult((ProbeCandidate("primary", "ext2 superblock", "unsupported" if problem else "supported", (problem,) if problem else ()),))

    def open(self, input_set, candidate_id, options):
        if candidate_id != "primary" or options:
            raise ValueError("Unsupported ext2 opening options")
        source_id = input_set.source_ids[0]
        data = input_set.read_at(source_id, SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE)
        if not magic_matches(data):
            raise ValueError("Not an ext2 image")
        superblock = decode_superblock(data)
        problem = support_problem(superblock, input_set.size_of(source_id))
        if problem:
            raise ValueError(problem)
        return Ext2Session(source_id, superblock)


class Ext2Session:
    def __init__(self, source_id, superblock):
        self.source_id = source_id
        self.superblock = superblock
        self.root_ref = NodeRef(uuid4().hex, "current", "superblock")
        self.closed = False

    def contexts(self):
        return (Context("current", "Current image"),)

    def roots(self, context_id):
        if context_id != "current":
            raise KeyError(context_id)
        return (self.root_ref,)

    def get_node(self, ref):
        if self.closed or ref != self.root_ref:
            raise KeyError(ref)
        return superblock_node(self.superblock, self.source_id, ref)

    def list_links(self, ref, cursor, limit):
        if self.closed or ref != self.root_ref or cursor is not None:
            raise KeyError(ref)
        return LinkPage(())

    def close(self):
        self.closed = True
