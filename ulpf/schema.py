"""
Every value in ECS_FIELDS is the coercion type applied by the normalizer:
    date        -> ISO-8601 UTC string
    keyword     -> str
    text        -> str
    long        -> int
    float       -> float
    ip          -> str (validated ip literal)
    boolean     -> bool
    keyword[]   -> list[str]   (scalars are wrapped)
    ip[]        -> list[str]
    object[]    -> list[dict]
    duration    -> int nanoseconds (plugins supply SECONDS, or "H:MM:SS")
"""

ECS_VERSION = "8.11"
ULPF_SCHEMA_VERSION = "1.0"

ECS_FIELDS = {
    # ---- base ----
    "@timestamp": "date",
    "message": "text",
    "tags": "keyword[]",
    "labels": "object",

    # ---- event ----
    "event.original": "text",          # RAW LOG, verbatim
    "event.id": "keyword",             # sha256(source:seq:raw)
    "event.hash": "keyword",           # sha256(raw)
    "event.ingested": "date",
    "event.created": "date",
    "event.kind": "keyword",           # event | alert | pipeline_error
    "event.category": "keyword[]",     # network | intrusion_detection | web | authentication | session | host | process ...
    "event.type": "keyword[]",         # connection | start | end | allowed | denied | access | info | error | protocol ...
    "event.action": "keyword",
    "event.outcome": "keyword",        # success | failure | unknown
    "event.severity": "long",          # NORMALIZED 0-10
    "event.module": "keyword",
    "event.dataset": "keyword",
    "event.provider": "keyword",
    "event.code": "keyword",           # vendor message id (ASA 302013, snort sid)
    "event.reason": "keyword",         # teardown reason, deny reason
    "event.duration": "duration",      # nanoseconds
    "event.timezone": "keyword",

    # ---- host / observer / process / user ----
    "host.name": "keyword",
    "host.hostname": "keyword",
    "host.ip": "ip[]",
    "observer.vendor": "keyword",
    "observer.product": "keyword",
    "observer.type": "keyword",        # firewall | ids | proxy | web-server | host
    "observer.name": "keyword",
    "observer.hostname": "keyword",
    "observer.ingress.zone": "keyword",
    "observer.egress.zone": "keyword",
    "observer.ingress.interface.name": "keyword",
    "observer.egress.interface.name": "keyword",
    "process.name": "keyword",
    "process.pid": "long",
    "user.name": "keyword",
    "user.domain": "keyword",
    "user.effective.name": "keyword",

    # ---- source / destination ----
    "source.ip": "ip",
    "source.port": "long",
    "source.bytes": "long",
    "source.packets": "long",
    "source.domain": "keyword",
    "source.nat.ip": "ip",
    "source.nat.port": "long",
    "source.user.name": "keyword",
    "destination.ip": "ip",
    "destination.port": "long",
    "destination.bytes": "long",
    "destination.packets": "long",
    "destination.domain": "keyword",
    "destination.nat.ip": "ip",
    "destination.nat.port": "long",

    # ---- network ----
    "network.transport": "keyword",    # tcp | udp | icmp
    "network.protocol": "keyword",     # dns | http | ssl | smb
    "network.iana_number": "keyword",
    "network.direction": "keyword",    # inbound | outbound | internal | external
    "network.bytes": "long",
    "network.packets": "long",
    "network.community_id": "keyword",
    "network.type": "keyword",         # ipv4 | ipv6

    # ---- http / url / user_agent ----
    "http.request.method": "keyword",
    "http.request.referrer": "keyword",
    "http.request.bytes": "long",
    "http.request.body.bytes": "long",
    "http.response.status_code": "long",
    "http.response.bytes": "long",
    "http.response.body.bytes": "long",
    "http.response.mime_type": "keyword",
    "http.version": "keyword",
    "url.original": "keyword",
    "url.full": "keyword",
    "url.scheme": "keyword",
    "url.domain": "keyword",
    "url.port": "long",
    "url.path": "keyword",
    "url.query": "keyword",
    "user_agent.original": "keyword",

    # ---- dns ----
    "dns.id": "keyword",
    "dns.op_code": "keyword",
    "dns.question.name": "keyword",
    "dns.question.type": "keyword",
    "dns.question.class": "keyword",
    "dns.response_code": "keyword",
    "dns.answers": "object[]",         # [{data, ttl, type?}]
    "dns.resolved_ip": "ip[]",
    "dns.header_flags": "keyword[]",   # AA TC RD RA

    # ---- rule (ids / acl) ----
    "rule.id": "keyword",
    "rule.name": "keyword",
    "rule.category": "keyword",
    "rule.ruleset": "keyword",
    "rule.version": "keyword",

    # ---- log (transport) ----
    "log.level": "keyword",
    "log.logger": "keyword",
    "log.file.path": "keyword",
    "log.source.address": "keyword",
    "log.syslog.priority": "long",
    "log.syslog.facility.code": "long",
    "log.syslog.facility.name": "keyword",
    "log.syslog.severity.code": "long",
    "log.syslog.severity.name": "keyword",
    "log.syslog.hostname": "keyword",
    "log.syslog.appname": "keyword",
    "log.syslog.procid": "keyword",
    "log.syslog.msgid": "keyword",
    "log.syslog.version": "long",

    # ---- related (auto-derived pivots) ----
    "related.ip": "ip[]",
    "related.user": "keyword[]",
    "related.hosts": "keyword[]",
    "related.hash": "keyword[]",

    # ---- error (quarantine records only) ----
    "error.type": "keyword",
    "error.message": "text",
    "error.code": "keyword",
}

ECS_FIELD_SET = frozenset(ECS_FIELDS)

# ---- custom namespaces (always present) ----
ULPF_FIELDS = {
    "ulpf.schema.version": "keyword",
    "ulpf.pipeline.version": "keyword",
    "ulpf.parser.name": "keyword",
    "ulpf.parser.version": "keyword",
    "ulpf.classification.log_type": "keyword",
    "ulpf.classification.confidence": "float",
    "ulpf.classification.candidates": "object[]",
    "ulpf.ingest.source": "keyword",
    "ulpf.ingest.seq": "long",         # line number / message counter within source
}

# ---- controlled vocabularies (ECS allowed values) ----
EVENT_KIND = frozenset({"event", "alert", "metric", "state", "enrichment", "signal", "pipeline_error"})
EVENT_CATEGORY = frozenset({
    "authentication", "configuration", "database", "driver", "email", "file", "host", "iam",
    "intrusion_detection", "malware", "network", "package", "process", "registry", "session",
    "threat", "vulnerability", "web",
})
EVENT_TYPE = frozenset({
    "access", "admin", "allowed", "change", "connection", "creation", "deletion", "denied", "end",
    "error", "group", "indicator", "info", "installation", "protocol", "start", "user",
})
EVENT_OUTCOME = frozenset({"success", "failure", "unknown"})

# fields harvested into related.* by the normalizer
RELATED_IP_SOURCES = ("source.ip", "destination.ip", "source.nat.ip", "destination.nat.ip", "host.ip", "dns.resolved_ip")
RELATED_USER_SOURCES = ("user.name", "source.user.name", "user.effective.name")
RELATED_HOST_SOURCES = ("host.name", "host.hostname", "observer.hostname", "url.domain", "destination.domain", "source.domain", "dns.question.name")

# syslog severity 0-7 -> normalized 0-10 (shared by ASA, RFC5424, etc.)
SYSLOG_SEVERITY_TO_10 = {0: 10, 1: 9, 2: 8, 3: 7, 4: 5, 5: 4, 6: 2, 7: 1}
SYSLOG_SEVERITY_NAME = {0: "emergency", 1: "alert", 2: "critical", 3: "error", 4: "warning", 5: "notice", 6: "informational", 7: "debug"}
SYSLOG_FACILITY_NAME = {0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog", 6: "lpr", 7: "news", 8: "uucp",
                        9: "cron", 10: "authpriv", 11: "ftp", 12: "ntp", 13: "security", 14: "console", 15: "solaris-cron",
                        16: "local0", 17: "local1", 18: "local2", 19: "local3", 20: "local4", 21: "local5", 22: "local6", 23: "local7"}
