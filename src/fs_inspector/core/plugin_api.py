from collections import namedtuple
from fs_inspector.core.models import _nonempty


API_VERSION = 1
class PluginDescriptor(namedtuple("PluginDescriptor", "id name plugin_version api_version capabilities", defaults=[frozenset()])):
    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        obj = super().__new__(cls, *args, **kwargs)
        obj._validate()
        return obj

    def _validate(self):
        for name in ("id", "name", "plugin_version"):
            _nonempty(getattr(self, name), name)
        if (
            isinstance(self.api_version, bool)
            or not isinstance(self.api_version, int)
            or self.api_version <= 0
        ):
            raise ValueError("api_version must be a positive integer")


class ProbeLimits(namedtuple("ProbeLimits", "max_read_bytes max_candidates", defaults=[64 * 1024, 16])):
    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        obj = super().__new__(cls, *args, **kwargs)
        obj._validate()
        return obj

    def _validate(self):
        for name in ("max_read_bytes", "max_candidates"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


class ProbeCandidate(namedtuple("ProbeCandidate", "candidate_id label status diagnostics", defaults=[()])):
    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        obj = super().__new__(cls, *args, **kwargs)
        obj._validate()
        return obj

    def _validate(self):
        _nonempty(self.candidate_id, "candidate_id")
        _nonempty(self.label, "candidate label")
        if self.status not in ("supported", "partial", "needs_sources", "unsupported"):
            raise ValueError(f"unknown support status: {self.status}")


class ProbeResult(namedtuple("ProbeResult", "candidates diagnostics", defaults=[(), ()])):
    __slots__ = ()


class LinkPage(namedtuple("LinkPage", "links next_cursor", defaults=[None])):
    __slots__ = ()


class FilesystemSession:
    def contexts(self):
        raise NotImplementedError

    def roots(self, context_id):
        raise NotImplementedError

    def get_node(self, ref):
        raise NotImplementedError

    def list_links(self, ref, cursor, limit):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError


class FilesystemPlugin:
    descriptor = None

    def probe(self, input_set, limits):
        raise NotImplementedError

    def open(self, input_set, candidate_id, options):
        raise NotImplementedError
