import re
from typing import Optional

from ulpf.core.base import BaseParser, ParserRegistry
from ulpf.core.models import ParseResult, ParserContext
from ulpf.core.utils import make_envelope, safe_int


SNORT_RE = re.compile(
    r'^(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'\[\*\*\]\s+'
    r'\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+'
    r'(?P<msg>.*?)\s+\[\*\*\]\s+'
    r'\[Classification:\s*(?P<classification>[^\]]+)\]\s+'
    r'\[Priority:\s*(?P<priority>\d+)\]\s+'
    r'\{(?P<proto>[^}]+)\}\s+'
    r'(?P<src_ip>[^:\s]+)(?::(?P<src_port>\d+))?\s+->\s+'
    r'(?P<dst_ip>[^:\s]+)(?::(?P<dst_port>\d+))?$'
)


@ParserRegistry.register("snort.alert")
class SnortAlertParser(BaseParser):
    source_type = "snort.alert"
    parser_name = "snort_alert_parser"
    parser_version = "1.0"

    def parse(self, raw_event: str, context: Optional[ParserContext] = None) -> ParseResult:
        m = SNORT_RE.match(raw_event.strip())
        if not m:
            return self._error(raw_event, ["Snort alert parse failed"])

        g = m.groupdict()
        env = make_envelope(self.source_type, self.parser_name, self.parser_version, raw_event, None)
        env["event"]["category"] = ["intrusion_detection"]
        env["event"]["type"] = ["alert"]
        env["event"]["action"] = "snort_alert"
        env["event"]["outcome"] = "success"

        env["rule"] = {
            "gid": safe_int(g["gid"]),
            "sid": safe_int(g["sid"]),
            "rev": safe_int(g["rev"]),
            "name": g["msg"],
            "classification": g["classification"],
            "priority": safe_int(g["priority"]),
        }
        env["network"] = {
            "protocol": g["proto"],
        }
        env["source"] = {
            "ip": g["src_ip"],
            "port": safe_int(g["src_port"]),
        }
        env["destination"] = {
            "ip": g["dst_ip"],
            "port": safe_int(g["dst_port"]),
        }

        parsed = g
        return self._ok(raw_event, parsed, env)