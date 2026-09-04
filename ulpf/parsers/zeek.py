import json
from typing import Optional

from ulpf.core.base import BaseParser, ParserRegistry
from ulpf.core.models import ParseResult, ParserContext
from ulpf.core.utils import epoch_to_iso, make_envelope, safe_float, safe_int, normalize_url


class ZeekBaseParser(BaseParser):
    parser_name = "zeek_json_parser"
    parser_version = "1.0"

    def _load_json(self, raw_event: str):
        return json.loads(raw_event)


@ParserRegistry.register("zeek.conn")
class ZeekConnParser(ZeekBaseParser):
    source_type = "zeek.conn"
    parser_name = "zeek_conn_parser"

    def parse(self, raw_event: str, context: Optional[ParserContext] = None) -> ParseResult:
        try:
            data = self._load_json(raw_event)
        except Exception as e:
            return self._error(raw_event, [f"JSON parse error: {e}"])

        ts = epoch_to_iso(data.get("ts"))
        env = make_envelope(self.source_type, self.parser_name, self.parser_version, raw_event, ts)

        env["event"]["category"] = ["network"]
        env["event"]["type"] = ["connection"]
        env["event"]["action"] = "connection"
        env["event"]["outcome"] = "success" if data.get("conn_state") in ("SF", "S1", "S2", "S3") else None

        env["source"] = {
            "ip": data.get("id.orig_h"),
            "port": safe_int(data.get("id.orig_p")),
            "bytes": safe_int(data.get("orig_bytes")),
            "packets": safe_int(data.get("orig_pkts")),
            "local": data.get("local_orig"),
        }
        env["destination"] = {
            "ip": data.get("id.resp_h"),
            "port": safe_int(data.get("id.resp_p")),
            "bytes": safe_int(data.get("resp_bytes")),
            "packets": safe_int(data.get("resp_pkts")),
            "local": data.get("local_resp"),
        }
        env["network"] = {
            "transport": data.get("proto"),
            "application": data.get("service"),
            "iana_number": safe_int(data.get("ip_proto")),
            "duration": safe_float(data.get("duration")),
            "conn_state": data.get("conn_state"),
            "bytes": {
                "source_to_dest": safe_int(data.get("orig_bytes")),
                "dest_to_source": safe_int(data.get("resp_bytes")),
            },
            "packets": {
                "source_to_dest": safe_int(data.get("orig_pkts")),
                "dest_to_source": safe_int(data.get("resp_pkts")),
            },
            "history": data.get("history"),
            "missed_bytes": safe_int(data.get("missed_bytes")),
        }
        env["zeek"] = data
        return self._ok(raw_event, data, env)


@ParserRegistry.register("zeek.dns")
class ZeekDNSParser(ZeekBaseParser):
    source_type = "zeek.dns"
    parser_name = "zeek_dns_parser"

    def parse(self, raw_event: str, context: Optional[ParserContext] = None) -> ParseResult:
        try:
            data = self._load_json(raw_event)
        except Exception as e:
            return self._error(raw_event, [f"JSON parse error: {e}"])

        ts = epoch_to_iso(data.get("ts"))
        env = make_envelope(self.source_type, self.parser_name, self.parser_version, raw_event, ts)

        env["event"]["category"] = ["network"]
        env["event"]["type"] = ["protocol", "info"]
        env["event"]["action"] = "dns_query"
        env["event"]["outcome"] = "success" if data.get("rcode_name") == "NOERROR" else "failure"

        env["source"] = {
            "ip": data.get("id.orig_h"),
            "port": safe_int(data.get("id.orig_p")),
        }
        env["destination"] = {
            "ip": data.get("id.resp_h"),
            "port": safe_int(data.get("id.resp_p")),
        }
        env["dns"] = {
            "id": safe_int(data.get("trans_id")),
            "question": {
                "name": data.get("query"),
                "class": data.get("qclass_name"),
                "type": data.get("qtype_name"),
            },
            "response_code": {
                "code": safe_int(data.get("rcode")),
                "name": data.get("rcode_name"),
            },
            "answers": data.get("answers", []),
            "ttls": data.get("TTLs", []),
            "flags": {
                "AA": data.get("AA"),
                "TC": data.get("TC"),
                "RD": data.get("RD"),
                "RA": data.get("RA"),
            },
            "opcode": {
                "code": safe_int(data.get("opcode")),
                "name": data.get("opcode_name"),
            },
            "rejected": data.get("rejected"),
            "rtt": safe_float(data.get("rtt")),
        }
        env["zeek"] = data
        return self._ok(raw_event, data, env)


@ParserRegistry.register("zeek.http")
class ZeekHTTPParser(ZeekBaseParser):
    source_type = "zeek.http"
    parser_name = "zeek_http_parser"

    def parse(self, raw_event: str, context: Optional[ParserContext] = None) -> ParseResult:
        try:
            data = self._load_json(raw_event)
        except Exception as e:
            return self._error(raw_event, [f"JSON parse error: {e}"])

        ts = epoch_to_iso(data.get("ts"))
        env = make_envelope(self.source_type, self.parser_name, self.parser_version, raw_event, ts)

        method = data.get("method")
        host = data.get("host")
        uri = data.get("uri")

        env["event"]["category"] = ["network", "web"]
        env["event"]["type"] = ["access"]
        env["event"]["action"] = "http_request"
        env["event"]["outcome"] = "success" if safe_int(data.get("status_code")) and safe_int(data.get("status_code")) < 400 else "failure"

        env["source"] = {
            "ip": data.get("id.orig_h"),
            "port": safe_int(data.get("id.orig_p")),
        }
        env["destination"] = {
            "ip": data.get("id.resp_h"),
            "port": safe_int(data.get("id.resp_p")),
        }

        url = normalize_url(method, uri, host=host)

        env["http"] = {
            "request": {
                "method": method,
                "body": {
                    "bytes": safe_int(data.get("request_body_len")),
                },
            },
            "response": {
                "status_code": safe_int(data.get("status_code")),
                "status_message": data.get("status_msg"),
                "body": {
                    "bytes": safe_int(data.get("response_body_len")),
                },
                "mime_types": data.get("resp_mime_types", []),
            },
            "version": data.get("version"),
        }
        env["url"] = url
        env["user_agent"] = {
            "original": data.get("user_agent")
        }
        env["zeek"] = data
        return self._ok(raw_event, data, env)