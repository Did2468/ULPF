#!/usr/bin/env python3
import json, os, sys, tempfile, hashlib
sys.path.insert(0, os.getcwd())

results = []
def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not cond else ""))

ASA = '<166>May 14 12:00:43 FW-BO-EDGE %ASA-6-302014: Teardown TCP connection 1206841 for outside:74.172.69.175/2027 to dmz:10.44.30.10/110 duration 0:00:30 bytes 0 SYN Timeout'
SYSLOG = '<86>1 2024-05-14T12:00:39.083920Z WEB-BO-01 sshd 478027 - - pam_unix(sshd:session): session closed for user nina.kapoor'
FOREIGN = '1,2024/05/14 12:00:01,001801012345,TRAFFIC,end,2049,2024/05/14 12:00:01,10.1.1.5,8.8.8.8,0.0.0.0,0.0.0.0,allow-dns,,,dns,vsys1,trust,untrust'

print("== 1. imports")
try:
    import ulpf
    from ulpf.normalizer import get_path
    check("core imports", True)
except Exception as e:
    check("core imports", False, repr(e)); sys.exit(1)

print("== 2. classifier")
clf = ulpf.LogTypeClassifier(threshold=0.60)
p_asa, p_sys, p_for = clf.predict_batch([ASA, SYSLOG, FOREIGN])
check("ASA -> cisco_asa", p_asa["log_type"] == "cisco_asa", p_asa)
check("syslog -> syslog", p_sys["log_type"] == "syslog", p_sys)
check("foreign -> unknown", p_for["log_type"] == "unknown", p_for)

print("== 3. registry")
reg = ulpf.Registry("plugins")
check("no plugin load errors", not reg.errors, reg.errors)
check("cisco_asa present", "cisco_asa" in reg, reg.names())

print("== 4. envelope")
e1 = ulpf.make_envelope(ASA, "t.log", 7); e2 = ulpf.make_envelope(ASA, "t.log", 7); e3 = ulpf.make_envelope(ASA, "t.log", 8)
check("raw preserved", e1["raw"] == ASA)
check("event_id deterministic", e1["event_id"] == e2["event_id"])
check("event_id depends on seq", e1["event_id"] != e3["event_id"])
check("event_hash independent of seq", e1["event_hash"] == e3["event_hash"])

print("== 5. coercion")
ulpf.set_default_year(2024)
check("epoch ts", ulpf.coerce_ts(1715688013.17).startswith("2024-05-14T12:00:13"))
check("bsd ts uses year", ulpf.coerce_ts("May 14 12:00:13").startswith("2024-05-14"))
check("snort ts", ulpf.coerce_ts("05/14-12:02:39.796669").startswith("2024-05-14T12:02:39"))
check("duration H:MM:SS -> ns", ulpf.coerce_duration_ns("0:00:30") == 30_000_000_000)
check("duration float -> ns", ulpf.coerce_duration_ns(0.5) == 500_000_000)

print("== 6. pipeline end-to-end")
tmp = tempfile.mkdtemp(); inp = os.path.join(tmp, "mixed.log")
open(inp, "w").write("\n".join([ASA, SYSLOG, FOREIGN, "", ASA]) + "\n")
sink = ulpf.JsonlSink(os.path.join(tmp, "n.jsonl"))
with open(os.path.join(tmp, "q.jsonl"), "w") as qfh:
    q = ulpf.Quarantine(qfh, threshold=0.60)
    pipe = ulpf.Pipeline(clf, reg, sink, q, batch_size=2); pipe.process_file(inp); s = pipe.summary()
sink.close()
norm = [json.loads(l) for l in open(os.path.join(tmp, "n.jsonl"))]
quar = [json.loads(l) for l in open(os.path.join(tmp, "q.jsonl"))]
check("4 events (blank skipped)", s["events_total"] == 4, s)
check("normalized + quarantined == total", len(norm) + len(quar) == 4, (len(norm), len(quar)))
check("2 ASA normalized", sum(get_path(r, "event.dataset") == "cisco.asa" for r in norm) == 2)
errs = {get_path(r, "error.type") for r in quar}
check("foreign -> low_confidence", "low_confidence" in errs, errs)
check("syslog handled (plugin or no_plugin)", any(get_path(r, "event.dataset", "").endswith("syslog") for r in norm) or "no_plugin" in errs)

d = next(r for r in norm if get_path(r, "event.dataset") == "cisco.asa")
check("@timestamp 2024-05-14T12:00:43", str(d["@timestamp"]).startswith("2024-05-14T12:00:43"), d["@timestamp"])
check("source.ip / destination.ip", get_path(d, "source.ip") == "74.172.69.175" and get_path(d, "destination.ip") == "10.44.30.10")
check("ports are ints", get_path(d, "source.port") == 2027 and get_path(d, "destination.port") == 110)
check("network.transport tcp", get_path(d, "network.transport") == "tcp")
check("event.duration ns", get_path(d, "event.duration") == 30_000_000_000, get_path(d, "event.duration"))
check("event.severity 6 -> 2", get_path(d, "event.severity") == 2, get_path(d, "event.severity"))
check("event.action teardown", get_path(d, "event.action") == "teardown")
check("event.type [connection,end]", get_path(d, "event.type") == ["connection", "end"])
check("event.code 302014", get_path(d, "event.code") == "302014")
check("event.reason", get_path(d, "event.reason") == "SYN Timeout")
check("zones in observer", get_path(d, "observer.ingress.zone") == "outside" and get_path(d, "observer.egress.zone") == "dmz")
check("observer.type firewall", get_path(d, "observer.type") == "firewall")
check("log.syslog.facility local4", get_path(d, "log.syslog.facility.name") == "local4")
check("unmapped -> cisco.asa.connection_id", get_path(d, "cisco.asa.connection_id") == "1206841", get_path(d, "cisco"))
check("related.ip", set(get_path(d, "related.ip", [])) == {"74.172.69.175", "10.44.30.10"})
check("related.hosts", "FW-BO-EDGE" in get_path(d, "related.hosts", []))
check("ulpf.parser stamped", get_path(d, "ulpf.parser.name") == "cisco_asa")
check("ulpf.classification stamped", 0 <= get_path(d, "ulpf.classification.confidence", -1) <= 1)

print("== 7. traceability")
check("event.original == raw", get_path(d, "event.original") == ASA)
check("event.id recomputable", get_path(d, "event.id") == hashlib.sha256(f"{inp}:{get_path(d,'ulpf.ingest.seq')}:{ASA}".encode()).hexdigest())
check("event.hash == sha256(raw)", get_path(d, "event.hash") == hashlib.sha256(ASA.encode()).hexdigest())
check("log.file.path set", get_path(d, "log.file.path") == inp)
check("quarantine keeps event.original", all(get_path(r, "event.original") for r in quar))
check("quarantine kind pipeline_error", all(get_path(r, "event.kind") == "pipeline_error" for r in quar))
check("quarantine keeps candidates", all(get_path(r, "ulpf.classification.candidates") for r in quar))

print("== 8. full cisco_asa.log")
if os.path.exists("data/cisco_asa.log"):
    sink2 = ulpf.JsonlSink(os.path.join(tmp, "n2.jsonl"))
    with open(os.path.join(tmp, "q2.jsonl"), "w") as qfh:
        q2 = ulpf.Quarantine(qfh, 0.60); p2 = ulpf.Pipeline(clf, reg, sink2, q2); p2.process_file("data/cisco_asa.log"); s2 = p2.summary()
    sink2.close()
    check("success_rate 1.0", s2["success_rate"] == 1.0, s2)
    check(f"throughput {s2['eps']:,} eps", s2["eps"] > 0)

failed = [n for n, ok in results if not ok]
print(f"\n{len(results)-len(failed)}/{len(results)} passed" + (f"  -> FAILED: {failed}" if failed else "  -> ALL GOOD"))
sys.exit(1 if failed else 0)
