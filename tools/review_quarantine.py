#!/usr/bin/env python3
"""
Review quarantined events -> what should be onboarded / fixed next.

Clusters low_confidence lines by a masked template
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict

IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
HEX = re.compile(r"\b[0-9a-fA-F]{12,}\b")
NUM = re.compile(r"\d+")
WS = re.compile(r"\s+")


def template(raw: str) -> str:
    t = IP.sub("<IP>", raw)
    t = HEX.sub("<HEX>", t)
    t = NUM.sub("<N>", t)
    t = WS.sub(" ", t)
    return t[:160]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("quarantine", help="path to quarantine.jsonl")
    ap.add_argument("--top", type=int, default=10, help="clusters to show")
    ap.add_argument("--samples", type=int, default=2, help="sample lines per cluster")
    ap.add_argument("--export", help="write cluster raw lines to this directory")
    args = ap.parse_args()

    if not os.path.exists(args.quarantine):
        sys.exit(f"not found: {args.quarantine}")

    by_reason = Counter()
    parse_errors = defaultdict(list)          
    unknown = defaultdict(list)               
    no_plugin = Counter()

    with open(args.quarantine, encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            kind = rec["error"]["type"]
            detail = rec["error"]["message"]
            raw = rec["event"]["original"]
            cls = rec["ulpf"]["classification"]
            by_reason[kind] += 1
            if kind == "low_confidence":
                unknown[template(raw)].append(raw)
            elif kind == "parse_error":
                parse_errors[(cls["log_type"], detail[:80])].append(raw)
            elif kind == "no_plugin":
                no_plugin[detail] += 1

    total = sum(by_reason.values())
    print(f"== {total:,} quarantined events")
    for k, v in by_reason.most_common():
        print(f"   {k:16s} {v:>8,}")

    if no_plugin:
        print("\n== no_plugin (classifier knows the type, write the plugin):")
        for name, n in no_plugin.most_common():
            print(f"   {name:16s} {n:>8,}   -> create plugins/{name}/parser.py")

    if parse_errors:
        print("\n== parse_error (plugin exists, add a variant):")
        for (plugin, err), raws in sorted(parse_errors.items(), key=lambda kv: -len(kv[1]))[: args.top]:
            print(f"   [{plugin}] {len(raws):>6,}  {err}")
            for r in raws[: args.samples]:
                print(f"        {r[:150]}")

    if unknown:
        print(f"\n== low_confidence: {len(unknown)} distinct templates (top {args.top}) -> candidate new sources:")
        clusters = sorted(unknown.items(), key=lambda kv: -len(kv[1]))
        for i, (tpl, raws) in enumerate(clusters[: args.top], 1):
            print(f"\n   #{i}  {len(raws):>6,} events")
            print(f"       template: {tpl}")
            for r in raws[: args.samples]:
                print(f"       sample:   {r[:150]}")
        if args.export:
            os.makedirs(args.export, exist_ok=True)
            for i, (_, raws) in enumerate(clusters, 1):
                with open(os.path.join(args.export, f"cluster_{i}.log"), "w", encoding="utf-8") as fh:
                    fh.write("\n".join(raws) + "\n")
            print(f"\n   exported {len(clusters)} cluster files -> {args.export}/")


if __name__ == "__main__":
    main()
