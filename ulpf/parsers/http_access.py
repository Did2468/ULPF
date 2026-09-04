import re
from typing import Optional

from ulpf.core.base import BaseParser, ParserRegistry
from ulpf.core.models import ParseResult, ParserContext
from ulpf.core.utils import http_time_to_iso, make_envelope, normalize_url, parse_request_line, parse_kv_blob, safe_int


WEB_ACCESS_RE = re.compile(
    r'^(?P<client_ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)"$'
)

PROXY_ACCESS_RE = re.compile(
    r'^(?P<client_ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)"(?:\s+"(?P<extra>[^"]*)")?$'
)


@ParserRegistry.register("web.access")
class WebAccessParser(BaseParser):
    source_type = "web.access"
    parser_name = "web_access_parser"
    parser_version = "1.0"

    def parse(self, raw_event: str, context: Optional[ParserContext] = None) -> ParseResult:
        m = WEB_ACCESS_RE.match(raw_event.strip())
        if not m:
            return self._error(raw_event, ["Web access parse failed"])

        g = m.groupdict()
        ts = http_time_to_iso(g["ts"]) or g["ts"]
        req = parse_request_line(g["request"])
        url = normalize_url(req["method"], req["target"])

        env = make_envelope(self.source_type, self.parser_name, self.parser_version, raw_event, ts)
        env["event"]["category"] = ["web"]
        env["event"]["type"] = ["access"]
        env["event"]["action"] = "http_request"
        env["event"]["outcome"] = "success" if safe_int(g["status"]) and safe_int(g["status"]) < 400 else "failure"

        env["client"] = {"ip": g["client_ip"], "ident": g["ident"], "user": g["user"]}
        env["http"] = {
            "request": {
                "method": req["method"],
                "version": req["version"],
            },
            "response": {
                "status_code": safe_int(g["status"]),
                "body": {"bytes": safe_int(g["bytes"])},
            },
            "referrer": g["referrer"] if g["referrer"] != "-" else None,
            "user_agent": {"original": g["ua"]},
        }
        env["url"] = url
        env["web"] = {
            "request_line": g["request"],
        }
        return self._ok(raw_event, g, env)


@ParserRegistry.register("proxy.access")
class ProxyAccessParser(BaseParser):
    source_type = "proxy.access"
    parser_name = "proxy_access_parser"
    parser_version = "1.0"

    def parse(self, raw_event: str, context: Optional[ParserContext] = None) -> ParseResult:
        m = PROXY_ACCESS_RE.match(raw_event.strip())
        if not m:
            return self._error(raw_event, ["Proxy access parse failed"])

        g = m.groupdict()
        ts = http_time_to_iso(g["ts"]) or g["ts"]
        req = parse_request_line(g["request"])
        url = normalize_url(req["method"], req["target"])

        extra = parse_kv_blob(g["extra"] or "")
        env = make_envelope(self.source_type, self.parser_name, self.parser_version, raw_event, ts)
        env["event"]["category"] = ["network", "web"]
        env["event"]["type"] = ["access"]
        env["event"]["action"] = "proxy_request"
        env["event"]["outcome"] = "success" if safe_int(g["status"]) and safe_int(g["status"]) < 400 else "failure"

        env["client"] = {"ip": g["client_ip"], "ident": g["ident"], "user": g["user"]}
        env["http"] = {
            "request": {
                "method": req["method"],
                "version": req["version"],
            },
            "response": {
                "status_code": safe_int(g["status"]),
                "body": {"bytes": safe_int(g["bytes"])},
            },
            "referrer": g["referrer"] if g["referrer"] != "-" else None,
            "user_agent": {"original": g["ua"]},
        }
        env["url"] = url
        env["proxy"] = {
            "meta": extra,
            "request_line": g["request"],
        }

        return self._ok(raw_event, g, env)