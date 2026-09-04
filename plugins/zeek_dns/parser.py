"""
Zeek dns.log (JSON) to ECS.
"""

import ipaddress
import json

from ulpf.plugin import LogSourcePlugin


def flatten(d, parent="", out=None):
    out = {} if out is None else out
    for k, v in d.items():
        key = f"{parent}.{k}" if parent else k
        if isinstance(v, dict):
            flatten(v, key, out)
        else:
            out[key] = v
    return out


def _is_ip(s):
    try:
        ipaddress.ip_address(str(s)); return True
    except ValueError:
        return False


class Plugin(LogSourcePlugin):
    name, version = "zeek_dns", "2.0"
    module, dataset, provider = "zeek", "zeek.dns", "zeek"
    observer_vendor, observer_product, observer_type = "Zeek", "Zeek", "ids"
    event_category = ["network"]
    event_type = ["protocol"]

    field_map = {
        "ts": "@timestamp",
        "id.orig_h": "source.ip", "id.orig_p": "source.port",
        "id.resp_h": "destination.ip", "id.resp_p": "destination.port",
        "proto": "network.transport",
        "trans_id": "dns.id", "query": "dns.question.name",
        "qtype_name": "dns.question.type", "qclass_name": "dns.question.class",
        "rcode_name": "dns.response_code", "opcode_name": "dns.op_code",
        "rtt": "event.duration",
    }

    def parse(self, raw):
        f = flatten(json.loads(raw))
        f["network.protocol"] = "dns"

        answers = f.pop("answers", None) or []
        ttls = f.get("TTLs") or []
        if answers:
            f["dns.answers"] = [{"data": a, **({"ttl": int(t)} if t is not None else {})}
                                for a, t in zip(answers, ttls + [None] * (len(answers) - len(ttls)))]
            ips = [a for a in answers if _is_ip(a)]
            if ips:
                f["dns.resolved_ip"] = ips
        flags = [k for k in ("AA", "TC", "RD", "RA") if f.get(k)]
        if flags:
            f["dns.header_flags"] = flags
        for k in ("AA", "TC", "RD", "RA"):
            f.pop(k, None)

        rcode = f.get("rcode_name")
        f["event.outcome"] = "success" if rcode == "NOERROR" else ("failure" if rcode else "unknown")
        f["event.action"] = "dns_response" if (answers or rcode) else "dns_query"
        f["event.type"] = ["protocol", "info"]
        f["message"] = f"{f.get('query', '')} {f.get('qtype_name', '')} {rcode or ''}".strip()
        return f
