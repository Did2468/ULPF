"""
Plugin contract.
"""


class LogSourcePlugin:
    # ---- identity ----
    name: str = ""                  # == folder name == classifier label
    version: str = "1.0"
    module: str = "generic"         # event.module and unmapped namespace root
    dataset: str = ""               # event.dataset (default f"{module}.{name}")
    provider: str = ""              # event.provider

    observer_vendor: str = ""
    observer_product: str = ""
    observer_type: str = ""         # firewall | ids | proxy | web-server | host

    # ---- ECS classification defaults (used when parse() doesn't set them) ----
    event_kind: str = "event"
    event_category: list = ["network"]
    event_type: list = ["info"]

    # ---- normalization ----
    field_map: dict = {}            # source_field -> ECS dotted path
    severity_map: dict = {}         # raw severity -> 0-10 (applied to event.severity)

    def parse(self, raw: str) -> dict:
        raise NotImplementedError

    def post(self, fields: dict) -> dict:
        return {k: v for k, v in fields.items() if v not in (None, "")}

    def __repr__(self):
        return f"<Plugin {self.name} v{self.version} [{self.dataset or self.module + '.' + self.name}]>"
