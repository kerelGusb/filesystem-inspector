from collections import namedtuple
from importlib import metadata
from fs_inspector.core.plugin_api import API_VERSION, PluginDescriptor


ENTRY_POINT_GROUP = "fs_inspector.plugins"
class PluginDiagnostic(namedtuple("PluginDiagnostic", "entry_point code message")):
    __slots__ = ()


class DiscoveryResult(namedtuple("DiscoveryResult", "plugins diagnostics")):
    __slots__ = ()

    def plugin_for(self, plugin_id):
        for plugin in self.plugins:
            if plugin.descriptor.id == plugin_id:
                return plugin
        raise KeyError(plugin_id)


def discover_plugins():
    diagnostics = []
    loaded = []
    try:
        entries = metadata.entry_points(group=ENTRY_POINT_GROUP)
    except Exception as exc:
        return DiscoveryResult(
            (),
            (PluginDiagnostic(ENTRY_POINT_GROUP, "discovery_failed", _error_text(exc)),),
        )

    for entry in entries:
        origin = f"{entry.name} ({entry.value})"
        try:
            factory = entry.load()
            if not callable(factory):
                raise TypeError("entry point must resolve to a zero-argument factory")
            plugin = factory()
        except Exception as exc:
            diagnostics.append(PluginDiagnostic(origin, "load_failed", _error_text(exc)))
            continue

        try:
            descriptor = plugin.descriptor
            if not isinstance(descriptor, PluginDescriptor):
                raise TypeError("descriptor must be a PluginDescriptor")
            if not callable(getattr(plugin, "probe", None)):
                raise TypeError("plugin must implement probe")
            if not callable(getattr(plugin, "open", None)):
                raise TypeError("plugin must implement open")
        except Exception as exc:
            diagnostics.append(PluginDiagnostic(origin, "invalid_plugin", _error_text(exc)))
            continue
        loaded.append((origin, plugin, descriptor))

    by_id = {}
    for item in loaded:
        by_id.setdefault(item[2].id, []).append(item)

    accepted = []
    for plugin_id, registrations in sorted(by_id.items()):
        if len(registrations) > 1:
            names = ", ".join(origin for origin, _, _ in registrations)
            diagnostics.append(
                PluginDiagnostic(
                    plugin_id,
                    "duplicate_id",
                    f"Plugin id {plugin_id!r} is registered more than once: {names}",
                )
            )
            continue
        origin, plugin, descriptor = registrations[0]
        if descriptor.api_version != API_VERSION:
            diagnostics.append(
                PluginDiagnostic(
                    origin,
                    "incompatible_api",
                    f"Plugin {plugin_id!r} requires API {descriptor.api_version}; host supports {API_VERSION}",
                )
            )
            continue
        accepted.append(plugin)
    return DiscoveryResult(tuple(accepted), tuple(diagnostics))


def _error_text(exc):
    detail = str(exc)
    return f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__
