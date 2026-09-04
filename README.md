# ULPF — Universal Log Pre-processing Framework

A vendor-agnostic pipeline that turns heterogeneous perimeter network device logs
(firewalls, IDS/IPS, network monitors, proxies, syslog, web servers — in Syslog,
JSON, CEF-like, or plain-text form) into a single, lossless, ECS-normalized event
schema, ready for SIEM ingestion, correlation, threat hunting, and ML analytics.

Built for the "Universal Log Pre-processing Framework" Smart India Hackathon problem statement problem number-26156.see
[Problem statement coverage](#problem-statement-coverage) below for how each
requirement is met.

---

## Why

Every log source speaks a different language. Security teams end up writing and
maintaining a bespoke parser per vendor before any of that data is useful to a
SIEM, data lake, or ML model. ULPF replaces that per-source grind with:

- **One typed schema** (a profile of the Elastic Common Schema, ECS 8.11) that every
  source is normalized into.
- **A classifier that routes**, not parses — a lightweight ML model looks at each raw
  line and decides *which* plugin should handle it.
- **A plugin contract that never drops data** — every field a plugin doesn't map to
  a known ECS path is preserved under a `<module>.<dataset>.*` namespace instead of
  being discarded.
- **Full traceability** — every normalized event carries the verbatim raw log
  (`event.original`), a content hash, and an ingest sequence number back to the
  source file/line it came from.
- **A quarantine lane**, not a silent drop, for anything the classifier isn't
  confident about or that fails to parse — with tooling to cluster those events
  into candidates for the next plugin to build.

---

## Architecture

```
raw log line
     │
     ▼
┌─────────────────────┐   TF-IDF(char 2-5gram) + LogisticRegression
│  LogTypeClassifier   │   predicts: log_type, confidence, top-2 candidates
└─────────┬────────────┘
          │ confidence ≥ threshold?
   ┌──────┴───────┐
   │ no            │ yes
   ▼               ▼
Quarantine    ┌───────────────┐
(low_conf)    │   Registry     │  plugin for log_type exists?
              └───────┬────────┘
              ┌────────┴────────┐
              │ no                │ yes
              ▼                   ▼
        Quarantine          ┌───────────────┐
        (no_plugin)         │ Plugin.parse() │  regex / JSON → flat field dict
                            └───────┬────────┘
                             parse error?
                       ┌─────────────┴─────────────┐
                       │ yes                         │ no
                       ▼                             ▼
                 Quarantine                   ┌───────────────┐
                 (parse_error)                │   normalize()  │  coerce types, map
                                               │                │  to ECS paths, derive
                                               │                │  related.*, preserve
                                               │                │  unmapped fields
                                               └───────┬────────┘
                                                        ▼
                                                 normalized.jsonl
```

Every path — normalized or quarantined — carries `event.original`, `event.id`
(sha256 of source+seq+raw), `event.hash` (sha256 of raw), and
`ulpf.ingest.{source,seq}`, so any record can be traced back to its exact origin.

### Core modules (`ulpf/`)

| Module | Responsibility |
|---|---|
| `schema.py` | The ECS field profile: every field, its type, coercion rule, and controlled vocabularies (`event.category`, `event.type`, etc.) |
| `envelope.py` | Wraps each raw line with hash/id/timestamp *before* anything else happens — the lossless guarantee starts here |
| `classifier.py` | Loads the trained sklearn model, predicts `log_type` + confidence per batch |
| `registry.py` | Auto-discovers plugins under `plugins/*/parser.py`, validates their ECS field mappings and vocab at load time, self-tests each against its `samples.log` |
| `plugin.py` | The `LogSourcePlugin` contract every source plugin implements |
| `normalizer.py` | Coerces parsed fields into typed ECS values, derives `related.*` pivots, preserves unmapped fields under `<module>.<dataset>.*` |
| `quarantine.py` | Writes non-normalizable events to `quarantine.jsonl` with a reason, never silently drops anything |
| `pipeline.py` | Batches events, orchestrates classify → route → parse → normalize → sink |
| `sinks.py` | Output sinks (`JsonlSink`, `StdoutSink`, `MultiSink`); Kafka/OpenSearch/Parquet sinks are stubbed for SIEM/data-lake integration |

### Included plugins (`plugins/`)

`cisco_asa` (firewall) · `snort_alert` (IDS) · `syslog` (RFC5424/generic) ·
`zeek_conn` / `zeek_dns` / `zeek_http` (network monitor) · `proxy_access` ·
`web_access`

Each plugin is ~50–100 lines: a regex or JSON parser plus a `field_map` from
source-specific field names to ECS paths.

---

## Setup

### Requirements

- Python 3.10+
- `pip install -r requirements.txt` (numpy, scikit-learn 1.8.0, joblib)

### 1. Clone and install

```bash
git clone <repo-url> ulpf && cd ulpf
pip install -r requirements.txt
```

### 2. Train the classifier

Sample logs for each source live in `data/<log_type>.{log,json}` — the filename
(minus extension) becomes the classifier label and must match a plugin folder
name in `plugins/`.

```bash
python3 model.py
```

This trains a TF-IDF(char n-gram) + LogisticRegression classifier, prints a
classification report / confusion matrix, and saves:

- `models/log_type_clf.joblib`
- `models/model_meta.json`

### 3. Verify plugins + model load correctly

```bash
python3 run.py --check
```

Loads the classifier, auto-discovers and self-tests every plugin against its
`samples.log`, and reports any that fail validation (without processing any
input).

### 4. Run the pipeline

```bash
# Process a single file
python3 run.py --input input.log --out out

# Process a directory of logs
python3 run.py --input data/ --out out

# Multiple files/dirs, custom confidence threshold, year hint for year-less timestamps
python3 run.py --input mixed.log other.log --threshold 0.6 --year 2024

# Stream normalized JSON to stdout instead of a file
python3 run.py --input mixed.log --stdout | head -1 | python3 -m json.tool
```

**Outputs** (in `--out`, default `out/`):

- `normalized.jsonl` — one ECS document per line
- `quarantine.jsonl` — one error record per line (`error.type`, `error.message`,
  original raw event preserved)
- `metrics.json` — throughput (events/sec), success rate, per-source counts,
  quarantine breakdown by reason and type

### 5. Run in Docker (air-gapped friendly)

The image bundles the code, plugins, and pre-trained model — no external calls
at runtime, so it can run fully offline / air-gapped once built.

```bash
docker build -t ulpf .
docker run --rm -v $(pwd)/data:/app/input -v $(pwd)/out:/app/out \
    ulpf --input /app/input --out /app/out
```

---

## Onboarding a new log source

No code changes to the core pipeline are needed — just add a plugin.

```bash
python3 tools/new_plugin.py paloalto \
    --vendor "Palo Alto" --product PAN-OS --type firewall \
    --samples clusters/cluster_1.log
```

This scaffolds `plugins/paloalto/parser.py` (template regex + `field_map`) and
copies your sample lines to `plugins/paloalto/samples.log` and
`data/paloalto.log`. Then:

1. Edit the `PATTERN` regex and `field_map` in `parser.py` to map source fields
   to ECS paths (see `schema.py` for the full field list). Anything left
   unmapped is automatically preserved under `paloalto.paloalto.*` — nothing is
   lost even before you finish writing the mapping.
2. Retrain the classifier so it learns the new source: `python3 model.py`
3. Validate: `python3 run.py --check`

### Finding what to onboard next

Events the classifier can't confidently place, or that have no matching
plugin, land in `quarantine.jsonl` rather than being dropped.
`tools/review_quarantine.py` clusters those by a masked template (IPs, digits,
hex stripped out) so thousands of unknown lines collapse into a handful of
candidate new sources:

```bash
python3 tools/review_quarantine.py out/quarantine.jsonl --top 5 \
    --export unknown_clusters/
```

Each exported cluster file can be fed straight into `tools/new_plugin.py
--samples`.

### Exporting the schema

```bash
python3 tools/export_schema.py              # markdown field reference
python3 tools/export_schema.py --opensearch # OpenSearch/Elasticsearch index template mapping
```

---

## Output schema

Every normalized event is a single flat-nested JSON document following an ECS
8.11 profile (`ulpf/schema.py`), always including:

- `event.original` — the raw log line, verbatim (lossless requirement)
- `event.id` / `event.hash` — sha256-based identifiers for traceability
- `event.ingested` / `@timestamp` — pipeline receipt time and event time
- `event.category` / `event.type` / `event.outcome` — controlled-vocabulary
  classification fields shared across all sources, enabling cross-source
  correlation
- `related.ip` / `related.user` / `related.hosts` — auto-derived pivots for
  threat hunting and ML feature extraction
- `ulpf.*` — pipeline metadata: schema version, parser name/version,
  classifier confidence, ingest source/sequence
- Any source field with no ECS home, under `<module>.<dataset>.*`

See `tools/export_schema.py` output for the complete field reference.

---

## Sanity / robustness checks

```bash
python3 tools/sanity.py     # end-to-end smoke test across sample formats
python3 test67.py           # classifier robustness under perturbed IPs/hostnames/dates
```

---

## Problem statement coverage

| Requirement | How ULPF meets it |
|---|---|
| Lossless raw preservation | `event.original` + `event.hash` on every event, including quarantined ones |
| Source-specific extraction | Per-plugin regex/JSON parsers |
| Common taxonomy | ECS 8.11 profile with typed coercion |
| Traceability | `event.id`/`event.hash` + `ulpf.ingest.{source,seq}` |
| Plug-and-play onboarding | `LogSourcePlugin` contract, self-testing `Registry`, `tools/new_plugin.py` scaffolding |
| Unified visibility | Single schema across all sources |
| SIEM / data lake integration | JSONL sink today; OpenSearch index-template export via `tools/export_schema.py`; Kafka/OpenSearch/Parquet sinks stubbed in `sinks.py` |
| AI/ML-ready | Flat typed ECS fields + `related.*` pivots |
| Reduced parser effort | Shared normalizer/coercion layer; new plugin ≈ regex + field map |
| Air-gapped deployable | No runtime network calls; classifier is a local artifact |
| Container-packaged | `Dockerfile` included |

---
## FAQ

### Where does the test data come from?

ULPF uses **realistic synthetic security telemetry** generated using **Cisco Talos EvidenceForge**, an open-source security log generation project.

The generated data provides representative events across multiple security and network log formats for testing parsing, classification, normalization, and quarantine behavior.

### Are these real production logs?

No. The datasets used for development and validation are **synthetic**, designed to resemble realistic security telemetry without containing real production data.

### Can ULPF support a new log source?

Yes. A new source can be onboarded by adding a **parser plugin, field mapping, and representative training samples**. The core pipeline does not need to be modified.

