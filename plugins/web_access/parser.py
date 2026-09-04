"""
Apache/nginx combined access log (DMZ web server) to ECS.
"""

import re
from urllib.parse import urlsplit

from ulpf.plugin import LogSourcePlugin
#Re logic
RX = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+) HTTP/(?P<ver>[\d.]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"\s*$'
)

#Defining the plugin class
class Plugin(LogSourcePlugin):
    name, version = "web_access", "2.0"
    module, dataset, provider = "apache", "apache.access", "apache"
    observer_vendor, observer_product, observer_type = "Apache", "httpd", "web-server"
    event_category = ["web"]
    event_type = ["access"]

    def parse(self, raw):
        m = RX.match(raw)
        if not m:
            raise ValueError("apache combined mismatch")
        d = m.groupdict()
        nil = lambda v: None if v in ("-", "") else v
        status = int(d["status"])
        parts = urlsplit(d["url"])

        f = {
            "@timestamp": d["ts"],
            "source.ip": d["ip"], "user.name": nil(d["user"]), "ident": nil(d["ident"]),
            "http.request.method": d["method"], "http.version": d["ver"],
            "http.response.status_code": status,
            "http.response.body.bytes": 0 if d["bytes"] == "-" else int(d["bytes"]),
            "http.request.referrer": nil(d["ref"]), "user_agent.original": nil(d["ua"]),
            "url.original": d["url"], "url.path": parts.path or d["url"],
            "url.query": parts.query or None,
            "network.transport": "tcp", "network.protocol": "http",
            "event.action": "http_request",
            "event.outcome": "success" if status < 400 else "failure",
            "event.type": ["access", "denied"] if status in (401, 403) else (["access", "error"] if status >= 500 else ["access"]),
            "message": f"{d['method']} {d['url']} {status}",
        }
        if parts.hostname:                       # absolute URL in request line
            f["url.domain"], f["url.scheme"], f["url.full"] = parts.hostname, parts.scheme, d["url"]
        return f
