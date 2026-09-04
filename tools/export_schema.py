import json, sys
from ulpf.schema import ECS_FIELDS, ULPF_FIELDS, ECS_VERSION, ULPF_SCHEMA_VERSION

if "--opensearch" in sys.argv:                        # index template mapping
    es = {"date": "date", "keyword": "keyword", "text": "text", "long": "long", "float": "float",
          "ip": "ip", "boolean": "boolean", "keyword[]": "keyword", "ip[]": "ip", "object[]": "object",
          "object": "object", "duration": "long"}
    props = {}
    for path, t in {**ECS_FIELDS, **ULPF_FIELDS}.items():
        cur = props
        parts = path.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {"properties": {}})["properties"]
        cur[parts[-1]] = {"type": es[t]}
    print(json.dumps({"index_patterns": ["ulpf-*"], "template": {"mappings": {"properties": props}}}, indent=2))
else:                                                 # markdown
    print(f"# ULPF ECS profile (ECS {ECS_VERSION}, profile v{ULPF_SCHEMA_VERSION})\n")
    print("| field | type | notes |\n|---|---|---|")
    for path, t in ECS_FIELDS.items():
        print(f"| `{path}` | {t} | |")
    print("\n## ulpf.* (custom)\n\n| field | type |\n|---|---|")
    for path, t in ULPF_FIELDS.items():
        print(f"| `{path}` | {t} |")
