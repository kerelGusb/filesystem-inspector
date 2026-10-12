from collections import namedtuple
from pathlib import Path

from fs_inspector.core.discovery import discover_plugins
from fs_inspector.core.image_reader import FileImageReader
from fs_inspector.core.plugin_api import ProbeLimits
from fs_inspector.core.sources import SourceSet


class ImageOpenError(ValueError):
    pass


class InspectionError(ValueError):
    pass


class OpenedImage(namedtuple("OpenedImage", "path plugin_name source_id root_nodes")):
    __slots__ = ()


class InspectionController:
    def __init__(self):
        self._reader = None
        self._sources = None
        self._session = None

    def open_image(self, path):
        self.close()
        image_path = Path(path)
        try:
            reader = FileImageReader(image_path)
        except OSError as exc:
            raise ImageOpenError(f"Cannot open image {image_path}: {exc}") from exc

        session = None
        try:
            sources = SourceSet("image", reader)
            discovery = discover_plugins()
            reasons = [diagnostic.message for diagnostic in discovery.diagnostics]
            supported = []
            for plugin in discovery.plugins:
                try:
                    result = plugin.probe(sources, ProbeLimits())
                except Exception as exc:
                    reasons.append(f"{plugin.descriptor.name} probe failed: {exc}")
                    continue
                reasons.extend(result.diagnostics)
                for candidate in result.candidates:
                    if candidate.status == "supported":
                        supported.append((plugin, candidate))
                    else:
                        reasons.extend(candidate.diagnostics)

            if not supported:
                detail = "; ".join(reasons) or "no installed plugin recognized the image"
                raise ImageOpenError(f"Cannot inspect {image_path.name}: {detail}")
            if len(supported) != 1:
                raise ImageOpenError(
                    f"Several filesystem plugins matched {image_path.name}; "
                    "automatic selection is unavailable in this prototype"
                )

            plugin, candidate = supported[0]
            session = plugin.open(sources, candidate.candidate_id, {})
            contexts = session.contexts()
            if len(contexts) != 1:
                raise ImageOpenError("The prototype requires exactly one inspection context")
            refs = session.roots(contexts[0].id)
            if not refs:
                raise ImageOpenError("The selected plugin returned no root structures")
            nodes = tuple(session.get_node(ref) for ref in refs)
            self._reader = reader
            self._sources = sources
            self._session = session
            return OpenedImage(image_path, plugin.descriptor.name, sources.source_ids[0], nodes)
        except Exception as exc:
            try:
                if session is not None:
                    session.close()
            finally:
                reader.close()
            if isinstance(exc, ImageOpenError):
                raise
            raise ImageOpenError(f"Cannot inspect image {image_path}: {exc}") from exc

    def get_node(self, ref):
        if self._session is None:
            raise RuntimeError("No image is open")
        try:
            return self._session.get_node(ref)
        except (OSError, EOFError, ValueError, KeyError) as exc:
            raise self._inspection_error("structure", ref, exc) from exc

    def list_links(self, ref, cursor, limit):
        if self._session is None:
            raise RuntimeError("No image is open")
        try:
            return self._session.list_links(ref, cursor, limit)
        except (OSError, EOFError, ValueError, KeyError) as exc:
            raise self._inspection_error("links for", ref, exc) from exc

    def _inspection_error(self, action, ref, exc):
        if isinstance(exc, EOFError):
            category = "Incomplete image data"
        elif isinstance(exc, OSError):
            category = "Image read failed"
        elif isinstance(exc, KeyError):
            category = "Unknown or stale structure reference"
        else:
            category = "Malformed or unsupported filesystem data"
        return InspectionError(f"{category} while inspecting {action} {ref.key}: {exc}")

    def size_of(self, source_id):
        if self._sources is None:
            raise RuntimeError("No image is open")
        return self._sources.size_of(source_id)

    def read_at(self, source_id, offset, length):
        if self._sources is None:
            raise RuntimeError("No image is open")
        return self._sources.read_at(source_id, offset, length)

    def close(self):
        session, reader = self._session, self._reader
        self._session = None
        self._reader = None
        self._sources = None
        try:
            if session is not None:
                session.close()
        finally:
            if reader is not None:
                reader.close()
