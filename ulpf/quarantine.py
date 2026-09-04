import json
from collections import Counter


class Quarantine:
    def __init__(self, fh, threshold=None):
        self.fh, self.threshold = fh, threshold
        self.count, self.by_reason, self.by_type = 0, Counter(), Counter()

    def put(self, env, reason, classification):
        kind, _, detail = reason.partition(":")
        if kind == "low_confidence" and not detail:
            detail = f"classifier confidence {classification['confidence']} below threshold {self.threshold}"
        src = env["source"]
        rec = {
            "@timestamp": env["received_at"],
            "event": {"original": env["raw"], "id": env["event_id"], "hash": env["event_hash"],
                      "ingested": env["received_at"], "kind": "pipeline_error",
                      "category": ["network"], "type": ["error"],
                      "module": "ulpf", "dataset": "ulpf.quarantine"},
            "error": {"type": kind, "message": detail or kind},
            "log": ({"source": {"address": src}} if "://" in src else {"file": {"path": src}}),
            "ulpf": {"pipeline": {"version": env["pipeline_version"]},
                     "classification": classification,
                     "ingest": {"source": src, "seq": env["seq"]}},
        }
        self.fh.write(json.dumps(rec, default=str) + "\n")
        self.count += 1
        self.by_reason[kind] += 1
        self.by_type[classification.get("log_type", "unknown")] += 1

    def summary(self):
        return {"total": self.count, "by_reason": dict(self.by_reason), "by_type": dict(self.by_type)}
