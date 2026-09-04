"""
Squid-style proxy access log (Apache combined + trailing key=value field) -> ECS.
"""

import re
from urllib.parse import urlsplit

from ulpf.plugin import LogSourcePlugin
#regex pattern
RX = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+) HTTP/(?P<ver>[\d.]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
    r'(?: "(?P<extra>[^"]*)")?\s*$'
)
DENY_ACTIONS = {"deny", "denied", "block", "blocked", "reject"}

#Defining the plugin class 
class Plugin(LogSourcePlugin):
    name, version = "proxy_access", "2.0"
    module, dataset, provider = "squid", "squid.access", "squid"
    observer_vendor, observer_product, observer_type = "Squid", "Squid", "proxy"
    event_category = ["web", "network"]
    event_type = ["access"]

    def parse(self, raw):
        m = RX.match(raw)
        if not m:
            raise ValueError("proxy access mismatch")
        d = m.groupdict()
        nil = lambda v: None if v in ("-", "", None) else v
        status = int(d["status"])
        method, url = d["method"], d["url"]

        f = {
            "@timestamp": d["ts"],
            "source.ip": d["ip"], "ident": nil(d["ident"]),
            "http.request.method": method, "http.version": d["ver"],
            "http.response.status_code": status,
            "http.response.body.bytes": 0 if d["bytes"] == "-" else int(d["bytes"]),
            "http.request.referrer": nil(d["ref"]), "user_agent.original": nil(d["ua"]),
            "url.original": url,
            "network.transport": "tcp", "network.protocol": "http",
            "message": f"{method} {url} {status}",
        }

        # user: DOMAIN\user or plain
        user = nil(d["user"])
        if user:
            if "\\" in user:
                dom, _, u = user.rpartition("\\")
                f["user.domain"], f["user.name"] = dom, u
            else:
                f["user.name"] = user

        # url
        if method == "CONNECT":
            host, _, port = url.rpartition(":")
            f["url.domain"] = host or url
            if port.isdigit():
                f["url.port"] = int(port)
            f["url.scheme"] = "https"
            f["network.protocol"] = "ssl"
        else:
            p = urlsplit(url)
            if p.hostname:
                f["url.full"], f["url.domain"], f["url.scheme"] = url, p.hostname, p.scheme
                if p.port:
                    f["url.port"] = p.port
            f["url.path"] = p.path or "/"
            if p.query:
                f["url.query"] = p.query
        if f.get("url.domain"):
            f["destination.domain"] = f["url.domain"]

        # trailing key=value block
        kv = dict(t.split("=", 1) for t in (d["extra"] or "").split() if "=" in t)
        action = kv.pop("proxy_action", None)
        if "cs_bytes" in kv:  f["http.request.bytes"] = int(kv.pop("cs_bytes"))
        if "sc_bytes" in kv:  f["http.response.bytes"] = int(kv.pop("sc_bytes"))
        if "tunnel_cs_bytes" in kv: f["source.bytes"] = int(kv.pop("tunnel_cs_bytes"))
        if "tunnel_sc_bytes" in kv: f["destination.bytes"] = int(kv.pop("tunnel_sc_bytes"))
        if "tunnel_duration_ms" in kv: f["event.duration"] = int(kv.pop("tunnel_duration_ms")) / 1000.0
        if f.get("source.bytes") is not None or f.get("destination.bytes") is not None:
            f["network.bytes"] = (f.get("source.bytes") or 0) + (f.get("destination.bytes") or 0)
        f.update(kv)                                   # ssl_bump, byte_scope

        denied = (action or "").lower() in DENY_ACTIONS or status in (403, 407)
        f["event.action"] = f"proxy_{action}" if action else "proxy_request"
        f["event.outcome"] = "failure" if denied or status >= 400 else "success"
        f["event.type"] = ["access", "denied"] if denied else ["access", "allowed"]
        return f
