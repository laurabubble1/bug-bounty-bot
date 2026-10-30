from app.plugins.base import BaseScannerPlugin
from app.plugins.reflection import ParameterReflectionPlugin
from app.plugins.security_headers import SecurityHeadersPlugin

_PLUGINS: dict[str, BaseScannerPlugin] = {
    ParameterReflectionPlugin.key: ParameterReflectionPlugin(),
    SecurityHeadersPlugin.key: SecurityHeadersPlugin(),
}


def get_plugin(key: str) -> BaseScannerPlugin:
    try:
        return _PLUGINS[key]
    except KeyError as exc:
        raise ValueError(f"Unknown plugin: {key}") from exc


def list_plugins() -> list[dict[str, str]]:
    return [{"key": plugin.key, "description": plugin.description} for plugin in _PLUGINS.values()]
