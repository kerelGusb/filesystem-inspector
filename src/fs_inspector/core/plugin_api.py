from fs_inspector.core.models import _nonempty


API_VERSION = 1
class PluginDescriptor:
    def __init__(self, id, name, plugin_version, api_version, capabilities=frozenset()):
        self.id = id
        self.name = name
        self.plugin_version = plugin_version
        self.api_version = api_version
        self.capabilities = capabilities
        self._validate()

    def _validate(self):
        for name in ("id", "name", "plugin_version"):
            _nonempty(getattr(self, name), name)
        if (
            isinstance(self.api_version, bool)
            or not isinstance(self.api_version, int)
            or self.api_version <= 0
        ):
            raise ValueError("api_version must be a positive integer")


class ProbeLimits:
    def __init__(self, max_read_bytes=64 * 1024, max_candidates=16):
        self.max_read_bytes = max_read_bytes
        self.max_candidates = max_candidates
        self._validate()

    def _validate(self):
        for name in ("max_read_bytes", "max_candidates"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


class ProbeCandidate:
    def __init__(self, candidate_id, label, status, diagnostics=()):
        self.candidate_id = candidate_id
        self.label = label
        self.status = status
        self.diagnostics = diagnostics
        self._validate()

    def _validate(self):
        _nonempty(self.candidate_id, "candidate_id")
        _nonempty(self.label, "candidate label")
        if self.status not in ("supported", "partial", "needs_sources", "unsupported"):
            raise ValueError(f"unknown support status: {self.status}")


class ProbeResult:
    def __init__(self, candidates=(), diagnostics=()):
        self.candidates = candidates
        self.diagnostics = diagnostics


class LinkPage:
    def __init__(self, links, next_cursor=None):
        self.links = links
        self.next_cursor = next_cursor


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
