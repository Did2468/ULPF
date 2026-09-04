from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ParserContext:
    source_type: str
    ml_confidence: Optional[float] = None
    ingest_ts: Optional[str] = None
    reference_year: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParseResult:
    source_type: str
    parser_name: str
    parser_version: str
    raw_event: str
    parsed: Dict[str, Any] = field(default_factory=dict)
    normalized: Dict[str, Any] = field(default_factory=dict)
    parse_status: str = "success"   # success | partial | error
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "parser_name": self.parser_name,
            "parser_version": self.parser_version,
            "raw_event": self.raw_event,
            "parsed": self.parsed,
            "normalized": self.normalized,
            "parse_status": self.parse_status,
            "errors": self.errors,
        }