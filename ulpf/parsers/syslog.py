import re
from typing import Optional

from ulpf.core.base import BaseParser, ParserRegistry
from ulpf.core.models import ParseResult, ParserContext
from ulpf.core.utils import (
    make_envelope,
    parse_kv_blob,
    parse_syslog_pri,
    rfc3339_to_iso,
    safe_int,
)

SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<ver>\d+)\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<sd>\S+)\s*"
    r"(?P<msg>.*)$"
)

UFW_RE = re.compile(
    r"^\[(?P<kernel_ts>[^\]]+)\]\s+\[(?P<action>UFW BLOCK|UFW ALLOW|UFW AUDIT)\]\s+(?P<kv>.*)$"
)
SSHD_SESSION_RE = re.compile(
    r"^pam_unix\(sshd:session\):\s+(?P<action>session opened|session closed)\s+for user\s+(?P<user>.+)$"
)
SUDO_SESSION_RE = re.compile(
    r"^pam_unix\(sudo:session\):\s+(?P<action>session opened|session closed)\s+for user\s+(?P<user>.+)$"
)
SUDO_CMD_RE = re.compile(
    r"^(?P<invoker>[^:]+)\s*:\s*TTY=(?P<tty>[^;]+)\s*;\s*PWD=(?P<pwd>[^;]+)\s*;\s*USER=(?P<user>[^;]+)\s*;\s*COMMAND=(?P<command>.+)$"
)


@ParserRegistry.register("syslog.generic")
class GenericSyslogParser(BaseParser):
    source_type = "syslog.generic"
    parser_name = "generic_syslog_parser"
    parser_version = "1.0"

    def parse(self, raw_event: str, context: Optional[ParserContext] = None) -> ParseResult:
        m = SYSLOG_RE.match(raw_event.strip())
        if not m:
            return self._error(raw_event, ["RFC5424 syslog parse failed"])

        pri = safe_int(m.group("pri"))
        ts = rfc3339_to_iso(m.group("ts")) or m.group("ts")
        host = m.group("host")
        app = m.group("app")
        procid = m.group("procid")
        msgid = m.group("msgid")
        sd = m.group("sd")
        msg = m.group("msg").strip()

        env = make_envelope(self.source_type, self.parser_name, self.parser_version, raw_event, ts)
        env["observer"] = {"hostname": host}
        env["process"] = {
            "name": app if app != "-" else None,
            "pid": procid if procid != "-" else None,
        }
        pri_meta = parse_syslog_pri(pri) if pri is not None else {}

        env["syslog"] = {
            **pri_meta,
            "version": safe_int(m.group("ver")),
            "timestamp_raw": m.group("ts"),
            "structured_data": sd if sd != "-" else None,
            "message_id": msgid if msgid != "-" else None,
        }
        env["event"]["category"] = ["host"]
        env["event"]["action"] = "log_event"
        env["message"] = msg

        parsed = {
            "header": {
                "pri": pri,
                "version": safe_int(m.group("ver")),
                "timestamp": ts,
                "hostname": host,
                "app": app,
                "procid": procid,
                "msgid": msgid,
                "sd": sd,
            },
            "message": msg,
        }

        # --- UFW Subtype ---
        ufw = UFW_RE.match(msg)
        if ufw:
            g = ufw.groupdict()
            kv = parse_kv_blob(g["kv"])
            parsed["subtype"] = "ufw"
            parsed["details"] = {"kernel_ts": g["kernel_ts"], "action": g["action"], **kv}

            env["event"]["category"] = ["network", "security"]
            env["event"]["action"] = "firewall_block" if "BLOCK" in g["action"] else "firewall_allow"

            env["firewall"] = {
                "vendor": "ufw",
                "action": g["action"],
                "kernel_timestamp": g["kernel_ts"],
                "fields": kv,
            }
            env["source"] = {
                "interface": kv.get("IN"),
                "ip": kv.get("SRC"),
                "port": safe_int(kv.get("SPT")),
            }
            env["destination"] = {
                "interface": kv.get("OUT"),
                "ip": kv.get("DST"),
                "port": safe_int(kv.get("DPT")),
            }
            env["network"] = {
                "transport": (kv.get("PROTO") or "").lower() or None,
                "ttl": safe_int(kv.get("TTL")),
                "length": safe_int(kv.get("LEN")),
                "flags": {
                    "SYN": kv.get("SYN"),
                    "URGP": kv.get("URGP"),
                },
            }
            return self._ok(raw_event, parsed, env)

        # --- SSHD Subtype ---
        if app == "sshd":
            sshd = SSHD_SESSION_RE.match(msg)
            if sshd:
                parsed["subtype"] = "sshd_session"
                parsed["details"] = sshd.groupdict()
                env["event"]["category"] = ["authentication", "host"]
                env["event"]["action"] = sshd.group("action").replace(" ", "_")
                env["user"] = {"name": sshd.group("user")}
                return self._ok(raw_event, parsed, env)

        # --- SUDO Subtype ---
        if app == "sudo":
            sudo_session = SUDO_SESSION_RE.match(msg)
            if sudo_session:
                parsed["subtype"] = "sudo_session"
                parsed["details"] = sudo_session.groupdict()
                env["event"]["category"] = ["authentication", "host"]
                env["event"]["action"] = sudo_session.group("action").replace(" ", "_")
                env["user"] = {"name": sudo_session.group("user")}
                return self._ok(raw_event, parsed, env)

            sudo_cmd = SUDO_CMD_RE.match(msg)
            if sudo_cmd:
                g = sudo_cmd.groupdict()
                parsed["subtype"] = "sudo_command"
                parsed["details"] = g
                env["event"]["category"] = ["authentication", "host"]
                env["event"]["action"] = "sudo_command"
                env["user"] = {
                    "name": g["user"],
                    "effective": {"name": g["user"]},
                    "invoker": g["invoker"].strip(),
                }
                env["process"]["command_line"] = g["command"].strip()
                env["host"] = {
                    "working_directory": g["pwd"].strip(),
                    "tty": g["tty"].strip(),
                }
                return self._ok(raw_event, parsed, env)

        # --- Default / Generic Subtype ---
        parsed["subtype"] = "generic"
        return self._ok(raw_event, parsed, env)