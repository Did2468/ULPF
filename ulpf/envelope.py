import hashlib
import datetime as dt

PIPELINE_VERSION = "1.0.0"


def make_envelope(raw: str, source: str, seq: int) -> dict:
    return {
        "event_id": hashlib.sha256(f"{source}:{seq}:{raw}".encode("utf-8", "replace")).hexdigest(),
        "event_hash": hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest(),
        "raw": raw,
        "source": source,
        "seq": seq,
        "received_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
        "pipeline_version": PIPELINE_VERSION,
    }
