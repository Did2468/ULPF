# robustness.py
import re, random, joblib, numpy as np
m = joblib.load("models/log_type_clf.joblib")
random.seed(0)

def perturb(line):
    line = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
                  lambda _: ".".join(str(random.randint(1, 254)) for _ in range(4)), line)   # new IPs
    line = line.replace("May 14", "Nov 03").replace("2024-05-14", "2025-11-03") \
               .replace("14/May/2024", "03/Nov/2025").replace("05/14-", "11/03-")          # new date
    line = re.sub(r"\b(FW|WEB|PROXY|FILE|DC)-BO-\d+", "CORE-HQ-77", line)                    # new hostname
    line = re.sub(r"1715688\d+", lambda _: str(random.randint(1700000000, 1800000000)), line) # new epoch
    line = line.replace("northstar", "acme").replace("NORTHSTAR", "ACME")
    return line

import glob, os
for path in sorted(glob.glob("data/*")):
    label = os.path.splitext(os.path.basename(path))[0]
    lines = [l.rstrip("\n") for l in open(path, errors="replace") if l.strip()]
    sample = random.sample(lines, min(200, len(lines)))
    orig = m.predict_proba(sample); pert = m.predict_proba([perturb(l) for l in sample])
    acc_o = (m.classes_[orig.argmax(1)] == label).mean(); acc_p = (m.classes_[pert.argmax(1)] == label).mean()
    print(f"{label:14s} acc {acc_o:.3f} -> {acc_p:.3f}   mean conf {orig.max(1).mean():.3f} -> {pert.max(1).mean():.3f}"
          f"   min conf {pert.max(1).min():.3f}")
