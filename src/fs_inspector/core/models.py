from collections import namedtuple


def _nonempty(value, name):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a nonempty string")


class SourceRange(namedtuple("SourceRange", "source_id offset length")):
    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        obj = super().__new__(cls, *args, **kwargs)
        obj._validate()
        return obj

    def _validate(self):
        _nonempty(self.source_id, "source_id")
        for name in ("offset", "length"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")


class Context(namedtuple("Context", "id label")):
    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        obj = super().__new__(cls, *args, **kwargs)
        obj._validate()
        return obj

    def _validate(self):
        _nonempty(self.id, "context id")
        _nonempty(self.label, "context label")


class NodeRef(namedtuple("NodeRef", "session_id context_id key")):
    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        obj = super().__new__(cls, *args, **kwargs)
        obj._validate()
        return obj

    def _validate(self):
        _nonempty(self.session_id, "session_id")
        _nonempty(self.context_id, "context_id")
        _nonempty(self.key, "key")


class Field(namedtuple("Field", "name value description ranges", defaults=['', ()])):
    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        obj = super().__new__(cls, *args, **kwargs)
        obj._validate()
        return obj

    def _validate(self):
        _nonempty(self.name, "field name")


class Node(namedtuple("Node", "ref title kind fields ranges diagnostics", defaults=[(), (), ()])):
    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        obj = super().__new__(cls, *args, **kwargs)
        obj._validate()
        return obj

    def _validate(self):
        _nonempty(self.title, "node title")
        _nonempty(self.kind, "node kind")


class Link(namedtuple("Link", "label relation target target_has_links", defaults=[None])):
    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        obj = super().__new__(cls, *args, **kwargs)
        obj._validate()
        return obj

    def _validate(self):
        _nonempty(self.label, "link label")
        _nonempty(self.relation, "link relation")
        if self.target_has_links is not None and not isinstance(self.target_has_links, bool):
            raise ValueError("target_has_links must be a boolean or None")
