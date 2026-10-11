class UnknownSourceError(KeyError):
    pass


class SourceSet:
    def __init__(self, source_id, reader):
        if not isinstance(source_id, str) or not source_id:
            raise ValueError("source_id must be a nonempty string")
        self._source_id = source_id
        self._reader = reader
        self.source_ids = (source_id,)

    def size_of(self, source_id):
        self._check_id(source_id)
        return self._reader.size

    def read_at(self, source_id, offset, length):
        self._check_id(source_id)
        return self._reader.read_at(offset, length)

    def _check_id(self, source_id):
        if source_id != self._source_id:
            raise UnknownSourceError(source_id)
