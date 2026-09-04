"""
Log-type classifier: routes each raw event to a plugin name.
The model is a TF-IDF(char 2-5gram) + LogisticRegression sklearn Pipeline
trained by model.py. Labels == plugin folder names.
"""

import json
import os

import joblib
import numpy as np


class LogTypeClassifier:
    def __init__(self, model_path: str = "models/log_type_clf.joblib", threshold: float = 0.60):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"model not found: {model_path} (run model.py first)")
        self.model = joblib.load(model_path)
        self.threshold = threshold
        self.classes = [str(c) for c in self.model.classes_]

        meta_path = os.path.join(os.path.dirname(model_path), "model_meta.json")
        self.meta = json.load(open(meta_path)) if os.path.exists(meta_path) else {}

    def predict_batch(self, lines: list[str]) -> list[dict]:
        if not lines:
            return []
        proba = self.model.predict_proba(lines)
        top2 = np.argsort(proba, axis=1)[:, -2:][:, ::-1]
        out = []
        for p, (a, b) in zip(proba, top2):
            conf = float(p[a])
            out.append({
                "log_type": self.classes[a] if conf >= self.threshold else "unknown",
                "confidence": round(conf, 4),
                "candidates": [
                    [self.classes[a], round(conf, 4)],
                    [self.classes[b], round(float(p[b]), 4)],
                ],
            })
        return out

    def predict_one(self, line: str) -> dict:
        return self.predict_batch([line])[0]

    def __repr__(self):
        return f"<LogTypeClassifier classes={len(self.classes)} threshold={self.threshold}>"
