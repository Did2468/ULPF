import importlib.util
import pathlib
import sys

from .plugin import LogSourcePlugin
from .schema import ECS_FIELD_SET, EVENT_KIND, EVENT_CATEGORY, EVENT_TYPE


class PluginError(Exception):
    pass


class Registry:
    def __init__(self, plugin_dir="plugins", self_test=True, strict=False):
        self.plugin_dir = pathlib.Path(plugin_dir)
        self.plugins, self.errors = {}, {}
        if not self.plugin_dir.is_dir():
            raise FileNotFoundError(f"plugin dir not found: {plugin_dir}")
        for folder in sorted(p for p in self.plugin_dir.iterdir() if p.is_dir() and not p.name.startswith(("_", "."))):
            try:
                plugin = self._load(folder)
                self._validate(plugin, folder)
                if self_test:
                    self._self_test(plugin, folder)
                self.plugins[plugin.name] = plugin
            except Exception as e:  # noqa: BLE001
                msg = f"{type(e).__name__}: {e}"
                self.errors[folder.name] = msg
                if strict:
                    raise PluginError(f"plugin '{folder.name}' failed -> {msg}") from e
                print(f"[registry] SKIP {folder.name}: {msg}", file=sys.stderr)
        print(f"[registry] loaded {len(self.plugins)} plugin(s): {sorted(self.plugins)}"
              + (f"  | {len(self.errors)} failed: {sorted(self.errors)}" if self.errors else ""))

    def get(self, name): return self.plugins.get(name)
    def names(self): return sorted(self.plugins)
    def __contains__(self, name): return name in self.plugins
    def __len__(self): return len(self.plugins)

    def _load(self, folder):
        path = folder / "parser.py"
        if not path.exists():
            raise PluginError("parser.py missing")
        mod_name = f"ulpf_plugin_{folder.name}"
        spec = importlib.util.spec_from_file_location(mod_name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)
        cls = getattr(mod, "Plugin", None)
        if cls is None:
            raise PluginError("parser.py must define a class named `Plugin`")
        plugin = cls()
        if not isinstance(plugin, LogSourcePlugin):
            raise PluginError("`Plugin` must subclass ulpf.plugin.LogSourcePlugin")
        return plugin

    def _validate(self, p, folder):
        if p.name != folder.name:
            raise PluginError(f"Plugin.name '{p.name}' != folder '{folder.name}'")
        if p.event_kind not in EVENT_KIND:
            raise PluginError(f"event_kind '{p.event_kind}' not in {sorted(EVENT_KIND)}")
        if bad := [c for c in p.event_category if c not in EVENT_CATEGORY]:
            raise PluginError(f"event_category not ECS: {bad}")
        if bad := [t for t in p.event_type if t not in EVENT_TYPE]:
            raise PluginError(f"event_type not ECS: {bad}")
        if bad := [v for v in p.field_map.values() if v not in ECS_FIELD_SET]:
            raise PluginError(f"field_map targets non-ECS fields: {bad}")

    def _self_test(self, p, folder):
        samples = folder / "samples.log"
        if not samples.exists():
            return
        with open(samples, encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                line = line.rstrip("\r\n")
                if not line.strip():
                    continue
                try:
                    fields = p.post(p.parse(line))
                except Exception as e:
                    raise PluginError(f"samples.log line {i} failed -> {type(e).__name__}: {e}") from e
                if not isinstance(fields, dict):
                    raise PluginError(f"samples.log line {i}: parse() must return dict")
