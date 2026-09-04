from __future__ import annotations

from typing import Iterable, Iterator, Optional

from .base import ParserRegistry
from .loader import load_builtin_parsers
from .models import ParseResult, ParserContext


class LogDispatcher:
    SOURCE_ALIASES = {
        "conn.json": "zeek.conn",
        "dns.json": "zeek.dns",
        "http.json": "zeek.http",
        "zeek_conn": "zeek.conn",
        "zeek_dns": "zeek.dns",
        "zeek_http": "zeek.http",
        "cisco_asa": "cisco.asa",
        "ciscoasa": "cisco.asa",
        "syslog": "syslog.generic",
        "web_access": "web.access",
        "webaccess": "web.access",
        "proxy_access": "proxy.access",
        "proxyaccess": "proxy.access",
        "snort_alert": "snort.alert",
        "snortalert": "snort.alert",
    }

    def __init__(self, auto_load: bool = True):
        if auto_load:
            load_builtin_parsers()

    @classmethod
    def resolve_source_type(cls, source_type: str) -> str:
        normalized = (source_type or "").strip().lower()
        return cls.SOURCE_ALIASES.get(normalized, normalized)

    def dispatch(
        self,
        source_type: str,
        raw_event: str,
        context: Optional[ParserContext] = None,
    ) -> ParseResult:
        resolved = self.resolve_source_type(source_type)
        parser = ParserRegistry.create(resolved)

        if not parser:
            return ParseResult(
                source_type=resolved,
                parser_name="unknown",
                parser_version="0.0",
                raw_event=raw_event,
                parsed={},
                normalized={},
                parse_status="error",
                errors=[f"No parser registered for source_type='{source_type}' (resolved='{resolved}')"],
            )

        effective_context = context or ParserContext(source_type=source_type)
        return parser.parse(raw_event, effective_context)

    def dispatch_many(
        self,
        source_type: str,
        raw_events: Iterable[str],
        context: Optional[ParserContext] = None,
    ) -> Iterator[ParseResult]:
        for raw_event in raw_events:
            if raw_event is None:
                continue
            raw_event = raw_event.rstrip("\n")
            if not raw_event.strip():
                continue
            yield self.dispatch(source_type, raw_event, context)

    def supported_source_types(self) -> list[str]:
        return ParserRegistry.available()

    def supported_labels(self) -> list[str]:
        labels = set(ParserRegistry.available())
        labels.update(self.SOURCE_ALIASES.keys())
        return sorted(labels)