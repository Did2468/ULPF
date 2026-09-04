"""Normalizer: parsed field to  ECS document. See schema.py for the profile."""

import datetime as dt
import ipaddress
import os

from .schema import (ECS_FIELDS, ECS_FIELD_SET, ULPF_SCHEMA_VERSION,
                     RELATED_IP_SOURCES, RELATED_USER_SOURCES, RELATED_HOST_SOURCES)

_UTC = dt.timezone.utc
DEFAULT_YEAR = int(os.environ["ULPF_DEFAULT_YEAR"]) if os.environ.get("ULPF_DEFAULT_YEAR") else None


def set_default_year(year):
    global DEFAULT_YEAR
    DEFAULT_YEAR = int(year) if year else None


#nested helpers
def set_path(doc, path, value):
    parts = path.split(".")
    cur = doc
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = cur[p] = {}
        cur = nxt
    cur[parts[-1]] = value


def get_path(doc, path, default=None):
    cur = doc
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


#coercion
_TS_FORMATS = (
    ("%d/%b/%Y:%H:%M:%S %z", False), ("%b %d %H:%M:%S", True), ("%b  %d %H:%M:%S", True),
    ("%m/%d-%H:%M:%S.%f", True), ("%Y-%m-%d %H:%M:%S", False), ("%Y/%m/%d %H:%M:%S", False),
)


def coerce_ts(v):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return dt.datetime.fromtimestamp(float(v), _UTC).isoformat(timespec="milliseconds")
    s = str(v).strip()
    if not s:
        return None
    try:
        f = float(s)
        if 1e9 < f < 1e11:
            return dt.datetime.fromtimestamp(f, _UTC).isoformat(timespec="milliseconds")
    except ValueError:
        pass
    if "T" in s:
        try:
            d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
            d = d if d.tzinfo else d.replace(tzinfo=_UTC)
            return d.astimezone(_UTC).isoformat(timespec="milliseconds")
        except ValueError:
            pass
    now = dt.datetime.now(_UTC)
    year = DEFAULT_YEAR or now.year
    for fmt, needs_year in _TS_FORMATS:
        try:
            d = dt.datetime.strptime(s, fmt)
        except ValueError:
            continue
        if needs_year:
            d = d.replace(year=year)
            if DEFAULT_YEAR is None and d.replace(tzinfo=_UTC) > now + dt.timedelta(days=1):
                d = d.replace(year=year - 1)
        d = d if d.tzinfo else d.replace(tzinfo=_UTC)
        return d.astimezone(_UTC).isoformat(timespec="milliseconds")
    return s


def coerce_duration_ns(v):
    """seconds (number / numeric string / 'H:MM:SS') -> int nanoseconds."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return int(float(v) * 1e9)
    s = str(v).strip()
    if ":" in s:
        parts = [int(x) for x in s.split(":")]
        while len(parts) < 3:
            parts.insert(0, 0)
        h, m, sec = parts[-3:]
        return int((h * 3600 + m * 60 + sec) * 1e9)
    try:
        return int(float(s) * 1e9)
    except ValueError:
        return None


def _long(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return None


def _ip(v):
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        return None


def _list(v):
    return v if isinstance(v, list) else [v]


def coerce(path, v):
    t = ECS_FIELDS.get(path, "keyword")
    if t == "date":      return coerce_ts(v)
    if t == "duration":  return coerce_duration_ns(v)
    if t == "long":      return _long(v)
    if t == "float":
        try: return float(v)
        except (TypeError, ValueError): return None
    if t == "boolean":   return v.lower() in ("1", "true", "t", "yes") if isinstance(v, str) else bool(v)
    if t == "ip":        return _ip(v)
    if t == "ip[]":      return [x for x in (_ip(i) for i in _list(v)) if x] or None
    if t == "keyword[]": return [str(i) for i in _list(v)]
    if t == "object[]":  return _list(v)
    if t == "object":    return v if isinstance(v, dict) else None
    return str(v)


# ---------------------------------------------------------------- main
def normalize(env, plugin, fields):
    doc, unmapped = {}, {}

    for k, v in fields.items():
        if v is None or v == "":
            continue
        target = k if k in ECS_FIELD_SET else plugin.field_map.get(k)
        if target:
            cv = coerce(target, v)
            if cv is not None:
                set_path(doc, target, cv)
            else:
                unmapped[k] = v
        else:
            unmapped[k] = v

    # envelope to  ECS
    set_path(doc, "event.original", env["raw"])
    set_path(doc, "event.id", env["event_id"])
    set_path(doc, "event.hash", env["event_hash"])
    set_path(doc, "event.ingested", env["received_at"])
    if doc.get("@timestamp") is None:
        doc["@timestamp"] = env["received_at"]
    src = env["source"]
    set_path(doc, "log.source.address" if "://" in src else "log.file.path", src)

    # identity / classification defaults
    dataset = plugin.dataset or f"{plugin.module}.{plugin.name}"
    ev = doc.setdefault("event", {})
    ev.setdefault("kind", plugin.event_kind)
    ev.setdefault("category", list(plugin.event_category))
    ev.setdefault("type", list(plugin.event_type))
    ev.setdefault("outcome", "unknown")
    ev["module"], ev["dataset"] = plugin.module, dataset
    if plugin.provider:
        ev.setdefault("provider", plugin.provider)
    for attr, path in (("observer_vendor", "observer.vendor"), ("observer_product", "observer.product"),
                       ("observer_type", "observer.type")):
        if getattr(plugin, attr, "") and get_path(doc, path) is None:
            set_path(doc, path, getattr(plugin, attr))

    # severity normalization
    sev = ev.get("severity")
    if sev is not None and plugin.severity_map:
        mapped = plugin.severity_map.get(sev, plugin.severity_map.get(str(sev)))
        if mapped is not None:
            ev["severity"] = int(mapped)

    # case conventions
    for path in ("network.transport", "network.protocol", "network.direction"):
        val = get_path(doc, path)
        if isinstance(val, str):
            set_path(doc, path, val.lower())
    m = get_path(doc, "http.request.method")
    if isinstance(m, str):
        set_path(doc, "http.request.method", m.upper())

    # related
    ips, users, hosts = set(), set(), set()
    for p in RELATED_IP_SOURCES:
        if (val := get_path(doc, p)): ips.update(_list(val))
    for p in RELATED_USER_SOURCES:
        if (val := get_path(doc, p)): users.add(val)
    for p in RELATED_HOST_SOURCES:
        if (val := get_path(doc, p)): hosts.add(val)
    if ips:   set_path(doc, "related.ip", sorted(ips))
    if users: set_path(doc, "related.user", sorted(users))
    if hosts: set_path(doc, "related.hosts", sorted(hosts))

    # unmapped to  <module>.<dataset_short>
    if unmapped:
        short = dataset.split(".", 1)[1] if "." in dataset else plugin.name
        set_path(doc, f"{plugin.module}.{short}", unmapped)

    doc["ulpf"] = {
        "schema": {"version": ULPF_SCHEMA_VERSION},
        "pipeline": {"version": env["pipeline_version"]},
        "parser": {"name": plugin.name, "version": plugin.version},
        "ingest": {"source": src, "seq": env["seq"]},
    }
    return doc
