from abc import ABC, abstractmethod
from typing import Optional

from .models import ParseResult, ParserContext


class BaseParser(ABC):
    source_type: str = "base"
    parser_name: str = "base"
    parser_version: str = "1.0"

    @abstractmethod
    def parse(self, raw_event: str, context: Optional[ParserContext] = None) -> ParseResult:
        raise NotImplementedError

    def _ok(self, raw_event: str, parsed: dict, normalized: dict) -> ParseResult:
        return ParseResult(
            source_type=self.source_type,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            raw_event=raw_event,
            parsed=parsed,
            normalized=normalized,
            parse_status="success",
            errors=[],
        )

    def _partial(self, raw_event: str, parsed: dict, normalized: dict, errors: list[str]) -> ParseResult:
        return ParseResult(
            source_type=self.source_type,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            raw_event=raw_event,
            parsed=parsed,
            normalized=normalized,
            parse_status="partial",
            errors=errors,
        )

    def _error(self, raw_event: str, errors: list[str]) -> ParseResult:
        return ParseResult(
            source_type=self.source_type,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            raw_event=raw_event,
            parsed={},
            normalized={},
            parse_status="error",
            errors=errors,
        )


class ParserRegistry:
    _registry: dict[str, type[BaseParser]] = {}

    @classmethod
    def register(cls, source_type: str):
        def decorator(parser_cls: type[BaseParser]):
            parser_cls.source_type = source_type
            cls._registry[source_type] = parser_cls
            return parser_cls
        return decorator

    @classmethod
    def create(cls, source_type: str) -> Optional[BaseParser]:
        parser_cls = cls._registry.get(source_type)
        if not parser_cls:
            return None
        return parser_cls()

    @classmethod
    def available(cls) -> list[str]:
        return sorted(cls._registry.keys())