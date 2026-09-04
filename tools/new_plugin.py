#!/usr/bin/env python3
import argparse
import os
import shutil
import sys

TEMPLATE = '''"""
{name} plugin ({vendor} {product}) -> ECS.

TODO: paste one example line here and describe the format.
"""

import re

from ulpf.plugin import LogSourcePlugin

# TODO: write the pattern with named groups.
# Group names that are ECS paths cannot contain dots, so use short names and map them below.
PATTERN = re.compile(
    r"^(?P<ts>\\S+) (?P<host>\\S+) (?P<msg>.*)$"
)


class Plugin(LogSourcePlugin):
    name, version = "{name}", "0.1"
    module, dataset = "{module}", "{module}.{name}"
    observer_vendor, observer_product, observer_type = "{vendor}", "{product}", "{obs_type}"

    # ECS defaults when parse() does not set event.category / event.type
    event_category = ["network"]
    event_type = ["info"]

    # regex group -> ECS path. Anything not listed here (and not already an ECS path)
    # is kept under {module}.{name}.* -- nothing is dropped.
    field_map = {{
        "ts": "@timestamp",
        "host": "host.name",
        "msg": "message",
        # "src_ip": "source.ip", "src_port": "source.port",
        # "dst_ip": "destination.ip", "dst_port": "destination.port",
        # "proto": "network.transport", "action": "event.action", "user": "user.name",
    }}

    # optional: raw severity -> 0-10 (applied to event.severity)
    severity_map = {{}}

    def parse(self, raw: str) -> dict:
        m = PATTERN.match(raw)
        if not m:
            raise ValueError("{name}: pattern mismatch")
        f = m.groupdict()
        # TODO: derive event.action / event.type / event.outcome here if the source has them, e.g.
        # f["event.action"] = "allow"; f["event.type"] = ["connection", "allowed"]; f["event.outcome"] = "success"
        return f
'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name", help="plugin name == folder == classifier label, e.g. paloalto")
    ap.add_argument("--module", help="event.module / unmapped namespace (default: name)")
    ap.add_argument("--vendor", default="")
    ap.add_argument("--product", default="")
    ap.add_argument("--type", default="firewall", help="observer.type: firewall | ids | proxy | web-server | host")
    ap.add_argument("--samples", help="file of raw lines -> samples.log and data/<name>.log")
    ap.add_argument("--plugins", default="plugins")
    ap.add_argument("--data", default="data")
    args = ap.parse_args()

    name = args.name.lower()
    module = (args.module or name).lower()
    folder = os.path.join(args.plugins, name)
    if os.path.exists(folder):
        sys.exit(f"{folder} already exists")
    os.makedirs(folder)

    with open(os.path.join(folder, "parser.py"), "w") as fh:
        fh.write(TEMPLATE.format(name=name, module=module, vendor=args.vendor,
                                 product=args.product, obs_type=args.type))

    samples = os.path.join(folder, "samples.log")
    if args.samples:
        shutil.copy(args.samples, samples)
        os.makedirs(args.data, exist_ok=True)
        shutil.copy(args.samples, os.path.join(args.data, f"{name}.log"))
    else:
        open(samples, "w").close()

    print(f"created {folder}/parser.py, {samples}" + (f", {args.data}/{name}.log" if args.samples else ""))
    print("next:  edit PATTERN + field_map  ->  python3 model.py  ->  python3 run.py --check")


if __name__ == "__main__":
    main()
