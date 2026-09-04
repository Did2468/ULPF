"""Cisco ASA syslog -> ECS."""
import re

from ulpf.plugin import LogSourcePlugin
from ulpf.schema import SYSLOG_SEVERITY_TO_10, SYSLOG_SEVERITY_NAME, SYSLOG_FACILITY_NAME

HDR = re.compile(r"^<(?P<pri>\d+)>(?P<ts>\w{3}\s+\d{1,2}\s[\d:]{8})\s(?P<host>\S+)\s%ASA-(?P<sev>\d)-(?P<msg_id>\d+):\s(?P<body>.*)$")
BUILT = re.compile(
    r"^Built (?P<direction>inbound|outbound) (?P<proto>TCP|UDP) connection (?P<conn_id>\d+) for "
    r"(?P<src_zone>[\w-]+):(?P<src_ip>[\d.]+)/(?P<src_port>\d+) \((?P<src_nat_ip>[\d.]+)/(?P<src_nat_port>\d+)\) to "
    r"(?P<dst_zone>[\w-]+):(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+) \((?P<dst_nat_ip>[\d.]+)/(?P<dst_nat_port>\d+)\)(?:\s+\((?P<user>[^)]+)\))?$")
TEARDOWN = re.compile(
    r"^Teardown (?P<proto>TCP|UDP) connection (?P<conn_id>\d+) for "
    r"(?P<src_zone>[\w-]+):(?P<src_ip>[\d.]+)/(?P<src_port>\d+) to (?P<dst_zone>[\w-]+):(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+) "
    r"duration (?P<duration>\d+:\d{2}:\d{2}) bytes (?P<bytes>\d+)(?:\s+(?P<reason>.+?))?(?:\s+\((?P<user>[^)]+)\))?$")
ICMP = re.compile(
    r"^(?P<verb>Built|Teardown) (?P<direction>inbound |outbound )?ICMP connection for "
    r"faddr (?P<src_ip>[\d.]+)/(?P<icmp_id>\d+) gaddr (?P<dst_nat_ip>[\d.]+)/\d+ laddr (?P<dst_ip>[\d.]+)/\d+")
DENY = re.compile(
    r"^Deny (?P<proto>\w+) src (?P<src_zone>[\w-]+):(?P<src_ip>[\d.]+)(?:/(?P<src_port>\d+))? "
    r"dst (?P<dst_zone>[\w-]+):(?P<dst_ip>[\d.]+)(?:/(?P<dst_port>\d+))?(?: \(type (?P<icmp_type>\d+), code (?P<icmp_code>\d+)\))?"
    r" by access-group \"(?P<acl>[^\"]+)\"")

#Source name to ECS mapping 
MAP = {
    "src_ip": "source.ip", "src_port": "source.port", "src_nat_ip": "source.nat.ip", "src_nat_port": "source.nat.port",
    "dst_ip": "destination.ip", "dst_port": "destination.port", "dst_nat_ip": "destination.nat.ip", "dst_nat_port": "destination.nat.port",
    "src_zone": "observer.ingress.zone", "dst_zone": "observer.egress.zone",
    "proto": "network.transport", "direction": "network.direction", "duration": "event.duration",
    "bytes": "network.bytes", "reason": "event.reason", "user": "user.name", "acl": "rule.name",
    "conn_id": "connection_id",   # no ECS home -> cisco.asa.connection_id
}


class Plugin(LogSourcePlugin):
    name, version = "cisco_asa", "2.0"
    module, dataset, provider = "cisco", "cisco.asa", "asa"
    observer_vendor, observer_product, observer_type = "Cisco", "ASA", "firewall"
    event_category = ["network"]
    event_type = ["info"]
    severity_map = SYSLOG_SEVERITY_TO_10

    def parse(self, raw):
        m = HDR.match(raw)
        if not m:
            raise ValueError("ASA header mismatch")
        h = m.groupdict()
        pri, sev = int(h["pri"]), int(h["sev"])
        body = h["body"]
        f = {
            "@timestamp": h["ts"], "message": body,
            "observer.hostname": h["host"], "host.name": h["host"],
            "event.code": h["msg_id"], "event.severity": sev,
            "log.syslog.priority": pri, "log.syslog.facility.code": pri // 8,
            "log.syslog.facility.name": SYSLOG_FACILITY_NAME.get(pri // 8),
            "log.syslog.severity.code": sev, "log.syslog.severity.name": SYSLOG_SEVERITY_NAME.get(sev),
        }

        def take(match):
            for k, v in match.groupdict().items():
                if v is not None:
                    f[MAP.get(k, k)] = v.strip() if isinstance(v, str) else v

        if (b := BUILT.match(body)):
            take(b); f.update({"event.action": "built", "event.type": ["connection", "start"], "event.outcome": "success"})
        elif (b := TEARDOWN.match(body)):
            take(b); f.update({"event.action": "teardown", "event.type": ["connection", "end"], "event.outcome": "success"})
        elif (b := ICMP.match(body)):
            d = b.groupdict(); verb = d.pop("verb").lower()
            for k, v in d.items():
                if v: f[MAP.get(k, k)] = v.strip()
            f.update({"event.action": verb, "network.transport": "icmp",
                      "event.type": ["connection", "start" if verb == "built" else "end"], "event.outcome": "success"})
        elif (b := DENY.match(body)):
            take(b); f.update({"event.action": "deny", "event.type": ["connection", "denied"], "event.outcome": "failure"})
        return f
