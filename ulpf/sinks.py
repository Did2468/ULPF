"""
Output sinks for normalized events. All sinks implement write(record) or close().
JSONL is the default; the others are stubs to fill in when needed.
"""

import json


class JsonlSink:
    def __init__(self, path: str):
        self.path = path
        self.fh = open(path, "w", encoding="utf-8")
        self.count = 0

    def write(self, record: dict):
        self.fh.write(json.dumps(record, default=str) + "\n")
        self.count += 1

    def close(self):
        self.fh.close()


class StdoutSink:
    def __init__(self):
        self.count = 0

    def write(self, record: dict):
        print(json.dumps(record, default=str))
        self.count += 1

    def close(self):
        pass


class MultiSink:
    """Fan-out to several sinks."""
    def __init__(self, *sinks):
        self.sinks = sinks
        self.count = 0

    def write(self, record: dict):
        for s in self.sinks:
            s.write(record)
        self.count += 1

    def close(self):
        for s in self.sinks:
            s.close()


# Placeholders for later (kept so the CLI can reference them):
# class KafkaSink:      topic per category, key = event_id
# class OpenSearchSink: bulk index into ulpf-events-YYYY.MM.DD
# class ParquetSink:    batched pyarrow writer, partitioned by log_type/date
