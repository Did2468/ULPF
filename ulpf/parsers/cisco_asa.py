import re
from typing import Optional

from ulpf.core.base import BaseParser, ParserRegistry
from ulpf.core.models import ParseResult, ParserContext
from ulpf.core.utils import make_envelope, rfc3164_to_iso, safe_int


ASA_HEADER_RE = re.compile(
    r'^<(?P<pri>\d+)>(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+%ASA-(?P<sev>\d+)-(?P<msgid>\d+):\s+(?P<body>.*)$'
)

ASA_BUILT_RE = re.compile(
    r'^Built\s+(?P<direction>inbound|outbound)\s+(?P<proto>TCP|UDP)\s+connection\s+'
    r'(?P<conn_id>\d+)\s+for\s+'
    r'(?P<src_if>[^:]+):(?P<src_ip>[^/]+)/(?P<src_port>\d+)\s+'
    r'\((?P<nat_src_ip>[^/]+)/(?P<nat_src_port>\d+)\)\s+to\s+'
    r'(?P<dst_if>[^:]+):(?P<dst_ip>[^/]+)/(?P<dst_port>\d+)\s+'
    r'\((?P<nat_dst_ip>[^/]+)/(?P<nat_dst_port>\d+)\)$'
)

ASA_TEARDOWN_RE = re.compile(
    r'^Teardown\s+(?P<proto>TCP|UDP)\s+connection\s+(?P<conn_id>\d+)\s+for\s+'
    r'(?P<src_if>[^:]+):(?P<src_ip>[^/]+)/(?P<src_port>\d+)\s+to\s+'
    r'(?P<dst_if>[^:]+):(?P<dst_ip>[^/]+)/(?P<dst_port>\d+)\s+'
    r'duration\s+(?P<dur_h>\d+):(?P<dur_m>\d+):(?P<dur_s>\d+)\s+bytes\s+(?P<bytes>\d+)'
    r'(?:\s+(?P<reason>.*))?$'
)


@ParserRegistry.register("cisco.asa")
class CiscoASAParser(BaseParser):
    source_type = "cisco.asa"
    parser_name = "cisco_asa_parser"
    parser_version = "1.0"

    def parse(self, raw_event: str, context: Optional[ParserContext] = None) -> ParseResult:
        m = ASA_HEADER_RE.match(raw_event.strip())
        if not m:
            return self._error(raw_event, ["ASA header parse failed"])

        year = (context.reference_year if context and context.reference_year else None) or 2024
        ts = rfc3164_to_iso(m.group("month"), m.group("day"), m.group("time"), year)
        body = m.group("body").strip()
        host = m.group("host")

        env = make_envelope(self.source_type, self.parser_name, self.parser_version, raw_event, ts)
        env["observer"] = {"hostname": host}
        env["syslog"] = {
            "priority": safe_int(m.group("pri")),
            "severity": safe_int(m.group("sev")),
            "message_id": safe_int(m.group("msgid")),
        }
        env["event"]["category"] = ["network", "firewall"]
        env["event"]["action"] = "firewall_event"

        parsed = {
            "header": {
                "priority": safe_int(m.group("pri")),
                "severity": safe_int(m.group("sev")),
                "message_id": safe_int(m.group("msgid")),
                "hostname": host,
                "timestamp": ts,
            },
            "body": body,
        }

        built = ASA_BUILT_RE.match(body)
        teardown = ASA_TEARDOWN_RE.match(body)

        if built:
            g = built.groupdict()
            parsed["type"] = "built"
            parsed["details"] = g

            env["event"]["action"] = "connection_built"
            env["event"]["outcome"] = "success"
            env["network"] = {
                "transport": g["proto"].lower(),
                "direction": g["direction"],
            }
            env["source"] = {
                "interface": g["src_if"],
                "ip": g["src_ip"],
                "port": safe_int(g["src_port"]),
                "nat": {
                    "ip": g["nat_src_ip"],
                    "port": safe_int(g["nat_src_port"]),
                },
            }
            env["destination"] = {
                "interface": g["dst_if"],
                "ip": g["dst_ip"],
                "port": safe_int(g["dst_port"]),
                "nat": {
                    "ip": g["nat_dst_ip"],
                    "port": safe_int(g["nat_dst_port"]),
                },
            }
            env["cisco_asa"] = {
                "connection_id": safe_int(g["conn_id"]),
                "direction": g["direction"],
            }
            return self._ok(raw_event, parsed, env)

        if teardown:
            g = teardown.groupdict()
            duration = (safe_int(g["dur_h"]) or 0) * 3600 + (safe_int(g["dur_m"]) or 0) * 60 + (safe_int(g["dur_s"]) or 0)
            parsed["type"] = "teardown"
            parsed["details"] = g

            env["event"]["action"] = "connection_teardown"
            env["event"]["outcome"] = "success"
            env["network"] = {
                "transport": g["proto"].lower(),
                "duration": duration,
            }
            env["source"] = {
                "interface": g["src_if"],
                "ip": g["src_ip"],
                "port": safe_int(g["src_port"]),
            }
            env["destination"] = {
                "interface": g["dst_if"],
                "ip": g["dst_ip"],
                "port": safe_int(g["dst_port"]),
            }
            env["cisco_asa"] = {
                "connection_id": safe_int(g["conn_id"]),
                "bytes": safe_int(g["bytes"]),
                "reason": g.get("reason"),
            }
            if g.get("reason"):
                env["event"]["outcome"] = "failure" if "Timeout" in g["reason"] or "Reset" in g["reason"] else "unknown"
            return self._ok(raw_event, parsed, env)

        # fallback: keep raw body
        parsed["type"] = "unknown_asa"
        parsed["details"] = {"body": body}
        env["cisco_asa"] = {"message": body}
        return self._partial(raw_event, parsed, env, ["Unrecognized ASA body format"])