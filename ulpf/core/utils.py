import re
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Any, Dict, Optional, Tuple


KV_RE = re.compile(r'([A-Za-z0-9_.-]+)=([^\s]*)')


def safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    try:
        if value is None or value == "" or value == "-":
            return default
        return int(value)
    except Exception:
        return default


def safe_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    try:
        if value is None or value == "" or value == "-":
            return default
        return float(value)
    except Exception:
        return default


def epoch_to_iso(ts: Any) -> Optional[str]:
    try:
        if ts is None or ts == "":
            return None
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def rfc3339_to_iso(ts: str) -> Optional[str]:
    try:
        if not ts:
            return None
        # handles "2024-05-14T12:00:13.245802Z"
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def http_time_to_iso(ts: str) -> Optional[str]:
    try:
        # "14/May/2024:12:00:42 +0000"
        dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def rfc3164_to_iso(month: str, day: str, time_str: str, year: int) -> Optional[str]:
    try:
        dt = datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def parse_kv_blob(blob: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    if not blob:
        return result
    for key, value in KV_RE.findall(blob):
        result[key] = value
    return result


def parse_request_line(request: str) -> Dict[str, Optional[str]]:
    """
    Parses: METHOD TARGET HTTP/1.1
    """
    out = {
        "method": None,
        "target": None,
        "version": None,
    }
    if not request:
        return out

    parts = request.strip().split()
    if len(parts) >= 2:
        out["method"] = parts[0]
        out["target"] = parts[1]
    if len(parts) >= 3 and parts[2].startswith("HTTP/"):
        out["version"] = parts[2].split("/", 1)[1]
    return out


def normalize_url(method: Optional[str], target: Optional[str], host: Optional[str] = None) -> Dict[str, Any]:
    """
    Builds a useful URL object for proxy/web/http logs.
    """
    url_obj: Dict[str, Any] = {
        "original": target,
        "scheme": None,
        "domain": None,
        "port": None,
        "path": None,
        "query": None,
    }

    if not target:
        return url_obj

    # Absolute URL
    if target.startswith("http://") or target.startswith("https://"):
        p = urlparse(target)
        url_obj["scheme"] = p.scheme
        url_obj["domain"] = p.hostname
        url_obj["port"] = p.port
        url_obj["path"] = p.path or "/"
        url_obj["query"] = p.query or None
        return url_obj

    # CONNECT host:port
    if method == "CONNECT" and ":" in target:
        h, p = target.rsplit(":", 1)
        url_obj["scheme"] = "https"
        url_obj["domain"] = h
        url_obj["port"] = safe_int(p)
        url_obj["path"] = None
        return url_obj

    # Path-only request
    if target.startswith("/"):
        url_obj["path"] = target
        url_obj["domain"] = host
        return url_obj

    # host:port without scheme
    if ":" in target:
        h, p = target.rsplit(":", 1)
        url_obj["domain"] = h
        url_obj["port"] = safe_int(p)
        url_obj["scheme"] = "https" if url_obj["port"] == 443 else "http"
        return url_obj

    # fallback
    url_obj["path"] = target
    url_obj["domain"] = host
    return url_obj


def make_envelope(source_type: str, parser_name: str, parser_version: str, raw_event: str, timestamp: Optional[str] = None) -> Dict[str, Any]:
    return {
        "schema_version": "ulpf.v1",
        "@timestamp": timestamp,
        "event": {
            "dataset": source_type,
            "kind": "event",
            "category": [],
            "type": [],
            "action": None,
            "outcome": None,
        },
        "parser": {
            "name": parser_name,
            "version": parser_version,
        },
        "raw_event": raw_event,
    }


def parse_syslog_pri(pri: int) -> Dict[str, Any]:
    facility = pri // 8
    severity = pri % 8
    return {
        "priority": pri,
        "facility": facility,
        "severity": severity,
    }