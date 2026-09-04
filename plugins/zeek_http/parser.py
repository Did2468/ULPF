"""
Zeek http.log (JSON) to ECS
"""

import json
from urllib.parse import urlsplit

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


class Plugin(LogSourcePlugin):
    name, version = "zeek_http", "2.0"
    module, dataset, provider = "zeek", "zeek.http", "zeek"
    observer_vendor, observer_product, observer_type = "Zeek", "Zeek", "ids"
    event_category = ["network", "web"]
    event_type = ["access"]

    field_map = {
        "ts": "@timestamp",
        "id.orig_h": "source.ip", "id.orig_p": "source.port",
        "id.resp_h": "destination.ip", "id.resp_p": "destination.port",
        "method": "http.request.method", "version": "http.version",
        "host": "url.domain", "uri": "url.original",
        "user_agent": "user_agent.original", "referrer": "http.request.referrer",
        "username": "user.name",
        "request_body_len": "http.request.body.bytes", "response_body_len": "http.response.body.bytes",
        "status_code": "http.response.status_code",
    }

    def parse(self, raw):
        f = flatten(json.loads(raw))
        f["network.transport"] = "tcp"
        f["network.protocol"] = "http"

        method, host, uri = f.get("method"), f.get("host"), f.get("uri") or ""
        if method == "CONNECT":
            h, _, p = uri.rpartition(":")
            f["url.domain"] = h or host
            if p.isdigit():
                f["url.port"] = int(p)
            f["url.full"] = uri
            f.pop("host", None)
        elif uri.startswith("/"):
            parts = urlsplit(uri)
            f["url.path"] = parts.path
            if parts.query:
                f["url.query"] = parts.query
            if host:
                f["url.full"] = f"http://{host}{uri}"
                f["url.scheme"] = "http"
        elif "://" in uri:                      # absolute URI (proxy-style)
            parts = urlsplit(uri)
            f["url.full"], f["url.scheme"], f["url.path"] = uri, parts.scheme, parts.path
            if parts.query:
                f["url.query"] = parts.query
            if parts.hostname:
                f["url.domain"] = parts.hostname; f.pop("host", None)
            if parts.port:
                f["url.port"] = parts.port

        mimes = f.get("resp_mime_types")
        if isinstance(mimes, list) and mimes:
            f["http.response.mime_type"] = mimes[0]

        sc = f.get("status_code")
        f["event.outcome"] = "unknown" if sc is None else ("success" if int(sc) < 400 else "failure")
        f["event.action"] = "http_request"
        f["message"] = f"{method or ''} {uri} {sc or ''}".strip()
        return f
