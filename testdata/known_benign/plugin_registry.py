# ©AngelaMos | 2026
# plugin_registry.py
#
# Dynamic import and getattr dispatch. Both are normal plugin-loader moves
# and neither is evidence of packing on its own.

import importlib
from typing import Any, Callable


class Registry:
    def __init__(self) -> None:
        self._plugins: dict[str, Any] = {}

    def load(self, dotted: str) -> Any:
        module_name, _, attr = dotted.rpartition(".")
        module = importlib.import_module(module_name)
        plugin = getattr(module, attr)
        self._plugins[dotted] = plugin
        return plugin

    def call(self, dotted: str, *args: Any, **kwargs: Any) -> Any:
        plugin: Callable[..., Any] = self._plugins[dotted]
        return plugin(*args, **kwargs)
