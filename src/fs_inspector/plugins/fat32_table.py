from collections import OrderedDict


def entry_kind(value):
    if value == 0:
        return "free"
    if value == 1 or 0x0FFFFFF0 <= value <= 0x0FFFFFF6:
        return "reserved"
    if value == 0x0FFFFFF7:
        return "bad"
    if value >= 0x0FFFFFF8:
        return "end of chain"
    return "next cluster"


class Fat32TableReader:
    def __init__(self, sources, source_id, layout):
        self.sources = sources
        self.source_id = source_id
        self.layout = layout
        self.sectors = OrderedDict()

    def raw_entry(self, copy, cluster):
        offset = self.layout.fat_offset(copy, cluster)
        sector = offset // 512
        if sector not in self.sectors:
            self.sectors[sector] = self.sources.read_at(self.source_id, sector * 512, 512)
            if len(self.sectors) > 32:
                self.sectors.popitem(last=False)
        self.sectors.move_to_end(sector)
        relative = offset % 512
        return int.from_bytes(self.sectors[sector][relative:relative + 4], "little")

    def entry(self, cluster):
        return self.raw_entry(self.layout.active_fat, cluster) & 0x0FFFFFFF


class Fat32ChainReader:
    def __init__(self, table, first_cluster):
        table.layout.check_cluster(first_cluster)
        self.table = table
        self.clusters = [first_cluster]
        self.seen = {first_cluster}
        self.finished = False

    def cluster_at(self, index):
        if not isinstance(index, int) or not 0 <= index < 65536:
            raise ValueError("Cluster-chain inspection is limited to 65536 clusters")
        if index - len(self.clusters) > 4096:
            raise ValueError("Inspect earlier chain pages before requesting this cluster")
        while len(self.clusters) <= index and not self.finished:
            value = self.table.entry(self.clusters[-1])
            kind = entry_kind(value)
            if kind == "end of chain":
                self.finished = True
                break
            if kind != "next cluster":
                raise ValueError(f"Broken cluster chain: {kind} FAT entry after cluster {self.clusters[-1]}")
            self.table.layout.check_cluster(value)
            if value in self.seen:
                raise ValueError(f"Cycle in FAT chain at cluster {value}")
            self.clusters.append(value)
            self.seen.add(value)
        if index >= len(self.clusters):
            return None
        cluster = self.clusters[index]
        value = self.table.entry(cluster)
        kind = entry_kind(value)
        if kind not in ("next cluster", "end of chain"):
            raise ValueError(f"Broken cluster chain: cluster {cluster} is marked {kind}")
        if kind == "next cluster":
            self.table.layout.check_cluster(value)
        return cluster
