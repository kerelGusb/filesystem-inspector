from fs_inspector.core.models import Field, Node, SourceRange
from fs_inspector.plugins.fat32_table import Fat32ChainReader, entry_kind


class Fat32FileCluster:
    def __init__(self, cluster, index, offset, length, diagnostics=()):
        self.cluster = cluster
        self.index = index
        self.offset = offset
        self.length = length
        self.diagnostics = diagnostics

    def node(self, source_id, ref):
        span = SourceRange(source_id, self.offset, self.length)
        fields = (
            Field("Logical cluster index", self.index),
            Field("Physical cluster", self.cluster),
            Field("Physical offset", self.offset),
            Field("File bytes in this cluster", self.length, ranges=(span,)),
        )
        return Node(ref, f"File cluster {self.index} (physical {self.cluster})", "file_cluster", fields, (span,), self.diagnostics)


class Fat32FileReader:
    def __init__(self, layout, table, entry):
        self.layout = layout
        self.table = table
        self.entry = entry
        self.cluster_count = (entry.size + layout.cluster_size - 1) // layout.cluster_size
        self.chain = Fat32ChainReader(table, entry.first_cluster) if entry.size else None

    def resolve(self, index):
        if not 0 <= index < self.cluster_count:
            raise ValueError("File cluster index is outside the file")
        cluster = self.chain.cluster_at(index)
        if cluster is None:
            raise ValueError("File chain ends before the declared file size")
        length = min(self.layout.cluster_size, self.entry.size - index * self.layout.cluster_size)
        value = self.table.entry(cluster)
        kind = entry_kind(value)
        diagnostics = []
        if index == self.cluster_count - 1 and kind != "end of chain":
            diagnostics.append("FAT chain continues beyond the declared file size")
        return Fat32FileCluster(cluster, index, self.layout.cluster_offset(cluster), length, tuple(diagnostics))
