import time
from collections import defaultdict

from .envelope import make_envelope
from .normalizer import normalize


class Pipeline:
    def __init__(self, classifier, registry, sink, quarantine, batch_size=5000):
        self.clf, self.registry, self.sink, self.q = classifier, registry, sink, quarantine
        self.batch_size = batch_size
        self.total, self.ok_by_type, self.started = 0, defaultdict(int), time.time()

    def process_stream(self, events, max_wait=1.0):
        buf, first = [], None
        for item in events:
            buf.append(item)
            first = first or time.time()
            if len(buf) >= self.batch_size or time.time() - first >= max_wait:
                self._process_batch(buf); buf, first = [], None
        if buf:
            self._process_batch(buf)

    def process_file(self, path):
        def gen():
            with open(path, encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    line = line.rstrip("\r\n")
                    if line.strip():
                        yield path, i, line
        self.process_stream(gen(), max_wait=float("inf"))

    def _process_batch(self, buf):
        preds = self.clf.predict_batch([raw for _, _, raw in buf])
        for (source, seq, raw), pred in zip(buf, preds):
            self.total += 1
            env = make_envelope(raw, source, seq)
            log_type = pred["log_type"]
            if log_type == "unknown":
                self.q.put(env, "low_confidence", pred); continue
            plugin = self.registry.get(log_type)
            if plugin is None:
                self.q.put(env, f"no_plugin:{log_type}", pred); continue
            try:
                fields = plugin.post(plugin.parse(raw))
            except Exception as e:  # noqa: BLE001
                self.q.put(env, f"parse_error:{type(e).__name__}:{e}", pred); continue
            rec = normalize(env, plugin, fields)
            rec["ulpf"]["classification"] = {"log_type": log_type, "confidence": pred["confidence"]}
            self.sink.write(rec)
            self.ok_by_type[log_type] += 1

    def summary(self):
        elapsed = max(time.time() - self.started, 1e-9)
        q = self.q.summary()
        return {"events_total": self.total, "normalized": self.sink.count, "quarantined": q["total"],
                "success_rate": round(self.sink.count / self.total, 4) if self.total else None,
                "seconds": round(elapsed, 2), "eps": int(self.total / elapsed),
                "per_type_ok": dict(self.ok_by_type), "quarantine": q}
