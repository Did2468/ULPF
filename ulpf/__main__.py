from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ulpf.core.dispatcher import LogDispatcher
from ulpf.core.models import ParserContext
import ulpf.parsers  # registers parsers


def iter_input_lines(input_file: str | None):
    if not input_file or input_file == "-":
        for line in sys.stdin:
            yield line
        return

    with Path(input_file).open("r", encoding="utf-8") as f:
        for line in f:
            yield line


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ULPF - Universal Log Pre-processing Framework")
    parser.add_argument("--source-type", help="Classifier output or parser label")
    parser.add_argument("--input-file", help="Input file path (defaults to stdin)", default="-")
    parser.add_argument("--reference-year", type=int, help="Reference year for yearless formats", default=None)
    parser.add_argument("--ml-confidence", type=float, help="Optional classifier confidence", default=None)
    parser.add_argument("--ingest-ts", help="Optional ingest timestamp", default=None)
    parser.add_argument("--pretty", action="store_true", help="Pretty print JSON output")
    parser.add_argument("--list-sources", action="store_true", help="List supported canonical labels and aliases")
    args = parser.parse_args(argv)

    dispatcher = LogDispatcher()

    if args.list_sources:
        for label in dispatcher.supported_labels():
            print(label)
        return 0

    if not args.source_type:
        parser.error("--source-type is required unless --list-sources is used")

    context = ParserContext(
        source_type=args.source_type,
        reference_year=args.reference_year,
        ml_confidence=args.ml_confidence,
        ingest_ts=args.ingest_ts,
    )

    indent = 2 if args.pretty else None

    for line in iter_input_lines(args.input_file):
        raw = line.rstrip("\n")
        if not raw.strip():
            continue

        result = dispatcher.dispatch(args.source_type, raw, context)
        print(json.dumps(result.to_dict(), indent=indent, ensure_ascii=False, default=str))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())