"""
Snort fast-format alerts to ECS parsing logic
"""

import re

from ulpf.plugin import LogSourcePlugin
#Re logic
RX = re.compile(
    r"^(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<name>.*?)\s+\[\*\*\]\s+(?:\[Classification:\s*(?P<cls>[^\]]+)\]\s+)?"
    r"\[Priority:\s*(?P<prio>\d+)\]\s+\{(?P<proto>\w+)\}\s+"
    r"(?P<sip>[\d.]+)(?::(?P<sport>\d+))?\s+->\s+(?P<dip>[\d.]+)(?::(?P<dport>\d+))?$"
)

#Defining the class
class Plugin(LogSourcePlugin):
    name, version = "snort_alert", "2.0"
    module, dataset, provider = "snort", "snort.alert", "snort"
    observer_vendor, observer_product, observer_type = "Snort", "Snort", "ids"
    event_kind = "alert"
    event_category = ["intrusion_detection"]
    event_type = ["info"]
    severity_map = {1: 9, 2: 6, 3: 3, 4: 1}     # snort priority 1 = most severe

    def parse(self, raw):
        m = RX.match(raw)
        if not m:
            raise ValueError("snort fast-format mismatch")
        d = m.groupdict()
        return {
            "@timestamp": d["ts"], "message": d["name"],
            "event.action": "alert", "event.outcome": "unknown",
            "event.severity": int(d["prio"]),
            "event.code": d["sid"],
            "rule.id": d["sid"], "rule.version": d["rev"], "rule.name": d["name"],
            "rule.category": d["cls"],
            "rule.ruleset": {"1": "snort", "3": "snort-so", "119": "http_inspect", "129": "stream5"}.get(d["gid"], f"gid-{d['gid']}"),
            "network.transport": d["proto"],
            "source.ip": d["sip"], "source.port": d["sport"],
            "destination.ip": d["dip"], "destination.port": d["dport"],
            "gid": d["gid"], "priority": int(d["prio"]),
        }
