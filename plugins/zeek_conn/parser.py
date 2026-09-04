"""
Zeek conn.log (JSON) to ECS conersion.
"""

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


# Zeek conn_state to (event.type,event.outcome)
CONN_STATE = {
    "SF":     (["connection", "end"], "success"),      # normal establishment and termination
    "S0":     (["connection", "start"], "unknown"),    # attempt seen, no reply
    "S1":     (["connection", "start"], "success"),    # established, not terminated
    "S2":     (["connection", "end"], "success"),
    "S3":     (["connection", "end"], "success"),
    "REJ":    (["connection", "denied"], "failure"),   # attempt rejected
    "RSTO":   (["connection", "end"], "success"),      # established, originator aborted
    "RSTR":   (["connection", "end"], "success"),
    "RSTOS0": (["connection", "denied"], "failure"),
    "RSTRH":  (["connection", "denied"], "failure"),
    "SH":     (["connection", "start"], "unknown"),
    "SHR":    (["connection", "start"], "unknown"),
    "OTH":    (["connection", "info"], "unknown"),
}

#defining the plugin class
class Plugin(LogSourcePlugin):
    name, version = "zeek_conn", "2.0"
    module, dataset, provider = "zeek", "zeek.conn", "zeek"
    observer_vendor, observer_product, observer_type = "Zeek", "Zeek", "ids"
    event_category = ["network"]
    event_type = ["connection"]

    field_map = {
        "ts": "@timestamp",
        "id.orig_h": "source.ip", "id.orig_p": "source.port",
        "id.resp_h": "destination.ip", "id.resp_p": "destination.port",
        "proto": "network.transport", "service": "network.protocol", "ip_proto": "network.iana_number",
        "duration": "event.duration",
        "orig_bytes": "source.bytes", "resp_bytes": "destination.bytes",
        "orig_pkts": "source.packets", "resp_pkts": "destination.packets",
    }

    def parse(self, raw):
        f = flatten(json.loads(raw))
        state = f.get("conn_state")
        etype, outcome = CONN_STATE.get(state, (["connection"], "unknown"))
        f["event.type"], f["event.outcome"] = etype, outcome
        f["event.action"] = f"connection_{state.lower()}" if state else "connection"

        lo, lr = f.get("local_orig"), f.get("local_resp")
        if lo is not None and lr is not None:
            f["network.direction"] = {(True, True): "internal", (True, False): "outbound",
                                      (False, True): "inbound", (False, False): "external"}[(bool(lo), bool(lr))]

        ob, rb = f.get("orig_bytes"), f.get("resp_bytes")
        if ob is not None or rb is not None:
            f["network.bytes"] = (ob or 0) + (rb or 0)
        op, rp = f.get("orig_pkts"), f.get("resp_pkts")
        if op is not None or rp is not None:
            f["network.packets"] = (op or 0) + (rp or 0)

        src = str(f.get("id.orig_h", ""))
        f["network.type"] = "ipv6" if ":" in src else "ipv4"
        f["message"] = f"{src}:{f.get('id.orig_p')} -> {f.get('id.resp_h')}:{f.get('id.resp_p')} {f.get('proto', '')} {state or ''}".strip()
        return f
