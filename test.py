import joblib
m = joblib.load("models/log_type_clf.joblib")
foreign = [
  '1,2024/05/14 12:00:01,001801012345,TRAFFIC,end,2049,2024/05/14 12:00:01,10.1.1.5,8.8.8.8,0.0.0.0,0.0.0.0,allow-dns,,,dns,vsys1,trust,untrust,ethernet1/2,ethernet1/1',
  'date=2024-05-14 time=12:00:01 devname="FGT60E" devid="FG60E123" logid="0000000013" type="traffic" subtype="forward" srcip=10.0.0.5 dstip=1.1.1.1 action="accept"',
  'May 14 12:00:01 dc01 Microsoft-Windows-Security-Auditing: 4624: An account was successfully logged on. Subject: Security ID: S-1-5-18',
  '2024-05-14T12:00:01Z kernel: [12345.678] iptables DROP IN=eth0 OUT= SRC=10.0.0.9 DST=10.0.0.1 PROTO=TCP SPT=51515 DPT=22',
]
for line, p in zip(foreign, m.predict_proba(foreign)):
    top = p.argmax()
    print(f"{m.classes_[top]:14s} conf={p[top]:.3f} | {line[:70]}")
