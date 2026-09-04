#!/usr/bin/env python3
"""
ULPF command-line entry point.

    python3 run.py --input data/ --out out
    python3 run.py --input mixed.log other.log --threshold 0.6 --year 2024
    python3 run.py --input mixed.log --stdout | head -1 | python3 -m json.tool
    python3 run.py --check                         # just load + self-test plugins
"""

import argparse
import glob
import json
import os
import sys

import ulpf


def collect_inputs(inputs):
    paths = []
    for p in inputs:
        if os.path.isdir(p):
            paths += sorted(f for f in glob.glob(os.path.join(p, "*")) if os.path.isfile(f))
        elif os.path.isfile(p):
            paths.append(p)
        else:
            print(f"[warn] not found: {p}", file=sys.stderr)
    return paths


def main():
    ap = argparse.ArgumentParser(prog="ulpf", description="Universal Log Pre-processing Framework")
    ap.add_argument("--input", "-i", nargs="+", help="log file(s) and/or directory(ies)")
    ap.add_argument("--out", "-o", default="out", help="output directory (default: out)")
    ap.add_argument("--model", default="models/log_type_clf.joblib")
    ap.add_argument("--plugins", default="plugins")
    ap.add_argument("--threshold", type=float, default=0.60, help="min classifier confidence (else quarantine)")
    ap.add_argument("--batch", type=int, default=5000)
    ap.add_argument("--year", type=int, help="year to assume for year-less timestamps (syslog/snort)")
    ap.add_argument("--stdout", action="store_true", help="write normalized events to stdout instead of file")
    ap.add_argument("--no-self-test", action="store_true", help="skip plugin samples.log self-test")
    ap.add_argument("--strict", action="store_true", help="abort if any plugin fails to load")
    ap.add_argument("--check", action="store_true", help="load model + plugins, print status, exit")
    ap.add_argument("--version", action="version", version=f"ulpf {ulpf.__version__}")
    args = ap.parse_args()

    if args.year:
        os.environ["ULPF_DEFAULT_YEAR"] = str(args.year)   # read by normalizer at import
        import importlib; importlib.reload(ulpf.normalizer)

    # ---- load components ----
    clf = ulpf.LogTypeClassifier(args.model, args.threshold)
    registry = ulpf.Registry(args.plugins, self_test=not args.no_self_test, strict=args.strict)

    missing = [c for c in clf.classes if c not in registry]
    if missing:
        print(f"[warn] classifier knows {missing} but no plugin folder exists -> those will be quarantined "
              f"as no_plugin", file=sys.stderr)

    print(f"[ulpf] {clf}")
    print(f"[ulpf] plugins: {registry.names()}")
    if args.check:
        sys.exit(1 if registry.errors else 0)

    if not args.input:
        ap.error("--input is required (or use --check)")
    paths = collect_inputs(args.input)
    if not paths:
        sys.exit("no input files")

    # ---- run ----
    os.makedirs(args.out, exist_ok=True)
    sink = ulfp_sink = ulpf.StdoutSink() if args.stdout else ulpf.JsonlSink(os.path.join(args.out, "normalized.jsonl"))
    with open(os.path.join(args.out, "quarantine.jsonl"), "w", encoding="utf-8") as qfh:
        quarantine = ulpf.Quarantine(qfh)
        pipe = ulpf.Pipeline(clf, registry, sink, quarantine, batch_size=args.batch)
        for p in paths:
            print(f"[ulpf] processing {p}", file=sys.stderr)
            pipe.process_file(p)
        summary = pipe.summary()
    sink.close()

    summary["inputs"] = paths
    summary["threshold"] = args.threshold
    summary["plugins"] = registry.names()
    summary["plugin_errors"] = registry.errors
    with open(os.path.join(args.out, "metrics.json"), "w") as fh:
        json.dump(summary, fh, indent=2)

    print(json.dumps(summary, indent=2), file=sys.stderr)
    print(f"[ulpf] normalized -> {args.out}/normalized.jsonl | quarantine -> {args.out}/quarantine.jsonl "
          f"| metrics -> {args.out}/metrics.json", file=sys.stderr)


if __name__ == "__main__":
    main()
