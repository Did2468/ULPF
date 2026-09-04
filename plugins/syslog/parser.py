"""
RFC 5424 syslog (perimeter hosts / appliances) to ECSi conversion.
"""

import re

from ulpf.plugin import LogSourcePlugin
from ulpf.schema import SYSLOG_SEVERITY_TO_10, SYSLOG_SEVERITY_NAME, SYSLOG_FACILITY_NAME
#Re logic
HDR = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d)\s(?P<ts>\S+)\s(?P<host>\S+)\s(?P<app>\S+)\s"
    r"(?P<pid>\S+)\s(?P<msgid>\S+)\s(?P<sd>-|(?:\[.*?\])+)\s?(?P<message>.*)$"
)
KERNEL_TS = re.compile(r"^\[\s*(?P<uptime>\d+\.\d+)\]\s*")
KV = re.compile(r"\b([A-Z]{2,})=(\S*)")
SUDO = re.compile(
    r"^(?P<user>\S+) : (?:TTY=(?P<tty>\S+) ; )?PWD=(?P<pwd>\S+) ; USER=(?P<target>\S+) ; COMMAND=(?P<command>.*)$"
)
PAM = re.compile(
    r"pam_unix\((?P<service>[^:]+):(?:session|auth)\): "
    r"(?:session (?P<sess>opened|closed) for user (?P<user>[\w.\-@]+)(?:\(uid=(?P<uid>\d+)\))?"
    r"(?: by (?P<by>[\w.\-@]+)\(uid=\d+\))?|authentication failure)"
)
SSHD_OK = re.compile(r"^Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port (?P<port>\d+)")
SSHD_FAIL = re.compile(
    r"^(?:Failed (?P<method>\w+) for (?:invalid user )?|Invalid user )(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)(?: port (?P<port>\d+))?"
)

#defining the plugin class
class Plugin(LogSourcePlugin):
    name, version = "syslog", "2.0"
    module, dataset, provider = "system", "system.syslog", "rfc5424"
    observer_type = "host"
    event_category = ["host"]
    event_type = ["info"]
    severity_map = SYSLOG_SEVERITY_TO_10

    def parse(self, raw):
        m = HDR.match(raw)
        if not m:
            raise ValueError("RFC5424 header mismatch")
        h = m.groupdict()
        pri = int(h["pri"]); fac, sev = pri // 8, pri % 8
        nil = lambda v: None if v in (None, "-") else v
        msg = h["message"]

        f = {
            "@timestamp": h["ts"], "message": msg,
            "host.name": h["host"], "observer.hostname": h["host"],
            "process.name": nil(h["app"]),
            "event.severity": sev,
            "log.syslog.priority": pri, "log.syslog.version": h["version"],
            "log.syslog.facility.code": fac, "log.syslog.facility.name": SYSLOG_FACILITY_NAME.get(fac),
            "log.syslog.severity.code": sev, "log.syslog.severity.name": SYSLOG_SEVERITY_NAME.get(sev),
            "log.syslog.hostname": h["host"], "log.syslog.appname": nil(h["app"]),
            "log.syslog.procid": nil(h["pid"]), "log.syslog.msgid": nil(h["msgid"]),
            "structured_data": nil(h["sd"]),
        }
        if f["log.syslog.procid"] and f["log.syslog.procid"].isdigit():
            f["process.pid"] = int(f["log.syslog.procid"])

        app = h["app"]

        #kernel firewall(UFW/iptables)
        if "[UFW " in msg or " IN=" in msg:
            body = msg
            if (k := KERNEL_TS.match(body)):
                f["kernel_uptime"] = float(k["uptime"]); body = body[k.end():]
            kv = dict(KV.findall(body))
            blocked = "BLOCK" in body or "DROP" in body
            f.update({
                "event.category": ["network"],
                "event.type": ["connection", "denied" if blocked else "allowed"],
                "event.action": "block" if blocked else "allow",
                "event.outcome": "success",
                "source.ip": kv.get("SRC"), "destination.ip": kv.get("DST"),
                "source.port": kv.get("SPT"), "destination.port": kv.get("DPT"),
                "network.transport": kv.get("PROTO"),
                "observer.ingress.interface.name": kv.get("IN") or None,
                "observer.egress.interface.name": kv.get("OUT") or None,
                "ttl": kv.get("TTL"), "ip_len": kv.get("LEN"), "ip_id": kv.get("ID"),
                "tcp_flags": " ".join(t for t in ("SYN", "ACK", "FIN", "RST") if f" {t} " in f" {body} ") or None,
            })

        #sudo
        elif app == "sudo" and (s := SUDO.match(msg)):
            d = s.groupdict()
            f.update({
                "event.category": ["process"], "event.type": ["start"], "event.action": "sudo",
                "event.outcome": "success",
                "user.name": d["user"], "user.effective.name": d["target"],
                "message": d["command"], "tty": d["tty"], "pwd": d["pwd"],
            })

        #pam_unix session/auth
        elif (p := PAM.search(msg)):
            d = p.groupdict()
            if d["sess"]:
                f.update({
                    "event.category": ["session"],
                    "event.type": ["start" if d["sess"] == "opened" else "end"],
                    "event.action": f"session_{d['sess']}", "event.outcome": "success",
                    "user.name": d["user"], "user.effective.name": d["by"], "uid": d["uid"],
                })
            else:
                f.update({"event.category": ["authentication"], "event.type": ["start"],
                          "event.action": "auth_failure", "event.outcome": "failure"})
            f["pam_service"] = d["service"]

        #sshd
        elif app == "sshd" and (s := SSHD_OK.match(msg)):
            d = s.groupdict()
            f.update({"event.category": ["authentication"], "event.type": ["start"],
                      "event.action": "ssh_login", "event.outcome": "success",
                      "user.name": d["user"], "source.ip": d["ip"], "source.port": d["port"],
                      "auth_method": d["method"]})
        elif app == "sshd" and (s := SSHD_FAIL.match(msg)):
            d = s.groupdict()
            f.update({"event.category": ["authentication"], "event.type": ["start"],
                      "event.action": "ssh_login", "event.outcome": "failure",
                      "user.name": d["user"], "source.ip": d["ip"], "source.port": d["port"],
                      "auth_method": d["method"]})

        return f
