from app.plugins.base import BaseScannerPlugin
from app.plugins.reflection import ParameterReflectionPlugin

_PLUGINS: dict[str, BaseScannerPlugin] = {
    ParameterReflectionPlugin.key: ParameterReflectionPlugin(),
}


def get_plugin(key: str) -> BaseScannerPlugin:
    try:
        return _PLUGINS[key]
    except KeyError as exc:
        raise ValueError(f"Unknown plugin: {key}") from exc


def list_plugins() -> list[dict[str, str]]:
    return [{"key": plugin.key, "description": plugin.description} for plugin in _PLUGINS.values()]
