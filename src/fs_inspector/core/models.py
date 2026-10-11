def _nonempty(value, name):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a nonempty string")


class SourceRange:
    def __init__(self, source_id, offset, length):
        self.source_id = source_id
        self.offset = offset
        self.length = length
        self._validate()

    def __eq__(self, other):
        if not isinstance(other, SourceRange):
            return NotImplemented
        return (
            self.source_id == other.source_id
            and self.offset == other.offset
            and self.length == other.length
        )

    def _validate(self):
        _nonempty(self.source_id, "source_id")
        for name in ("offset", "length"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")


class Context:
    def __init__(self, id, label):
        self.id = id
        self.label = label
        self._validate()

    def _validate(self):
        _nonempty(self.id, "context id")
        _nonempty(self.label, "context label")


class NodeRef:
    def __init__(self, session_id, context_id, key):
        self.session_id = session_id
        self.context_id = context_id
        self.key = key
        self._validate()

    def __eq__(self, other):
        if not isinstance(other, NodeRef):
            return NotImplemented
        return (
            self.session_id == other.session_id
            and self.context_id == other.context_id
            and self.key == other.key
        )

    def _validate(self):
        _nonempty(self.session_id, "session_id")
        _nonempty(self.context_id, "context_id")
        _nonempty(self.key, "key")


class Field:
    def __init__(self, name, value, description='', ranges=()):
        self.name = name
        self.value = value
        self.description = description
        self.ranges = ranges
        self._validate()

    def _validate(self):
        _nonempty(self.name, "field name")


class Node:
    def __init__(self, ref, title, kind, fields=(), ranges=(), diagnostics=()):
        self.ref = ref
        self.title = title
        self.kind = kind
        self.fields = fields
        self.ranges = ranges
        self.diagnostics = diagnostics
        self._validate()

    def _validate(self):
        _nonempty(self.title, "node title")
        _nonempty(self.kind, "node kind")


class Link:
    def __init__(self, label, relation, target, target_has_links=None):
        self.label = label
        self.relation = relation
        self.target = target
        self.target_has_links = target_has_links
        self._validate()

    def _validate(self):
        _nonempty(self.label, "link label")
        _nonempty(self.relation, "link relation")
        if self.target_has_links is not None and not isinstance(self.target_has_links, bool):
            raise ValueError("target_has_links must be a boolean or None")
