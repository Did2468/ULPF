#!/usr/bin/env python3
#used to train the classification model 
#importing the required modules
import glob, os, json, random, joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

DATA_DIR = "data"
MODEL_DIR = "models"
PER_CLASS = 20000          # cap per class so classes stay balanced
random.seed(42)

#loading the file (for now only .log and .json)
def load_file(path):
    ext = os.path.splitext(path)[1].lower()
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    lines = [l.rstrip("\r\n") for l in text.splitlines() if l.strip()]

    if ext == ".log":
        return lines

    if ext == ".json":
        # JSONL: one object per line -> keep line as-is
        if all(l.lstrip().startswith("{") for l in lines[:20]):
            return lines
        # Single JSON array / object wrapping an array -> one line per record
        data = json.loads(text)
        if isinstance(data, dict):
            data = next(v for v in data.values() if isinstance(v, list))
        return [json.dumps(rec, separators=(",", ":")) for rec in data]

    return []


# loading the data 
X, y = [], []
for path in sorted(glob.glob(f"{DATA_DIR}/*.log") + glob.glob(f"{DATA_DIR}/*.json")):
    label = os.path.splitext(os.path.basename(path))[0]
    lines = list(dict.fromkeys(load_file(path)))     # dedupe
    random.shuffle(lines)
    lines = lines[:PER_CLASS]
    X += lines
    y += [label] * len(lines)
    print(f"{label:15s} {len(lines):>7,d} samples  ({os.path.basename(path)})")

X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
print(f"\ntrain={len(X_tr):,d}  test={len(X_te):,d}  classes={len(set(y))}\n")

# Training the model using tfidf+logistic regression
model = Pipeline([
    ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5),
                              min_df=5, max_features=300_000, sublinear_tf=True)),
    ("clf", LogisticRegression(max_iter=2000, C=5.0, n_jobs=-1)),
])
model.fit(X_tr, y_tr)

#Model Evaluation
pred = model.predict(X_te)
labels = list(model.classes_)
print(classification_report(y_te, pred, digits=4))
print("accuracy:", round(accuracy_score(y_te, pred), 4))
print("\nconfusion matrix (rows=true, cols=pred):")
print("labels:", labels)
print(confusion_matrix(y_te, pred, labels=labels))

wrong = [(t, p, x) for t, p, x in zip(y_te, pred, X_te) if t != p]
if wrong:
    print(f"\n{len(wrong)} misclassified, first 10:")
    for t, p, x in wrong[:10]:
        print(f"  true={t:12s} pred={p:12s} | {x[:120]}")

# Saving the model joblib file
os.makedirs(MODEL_DIR, exist_ok=True)
joblib.dump(model, f"{MODEL_DIR}/log_type_clf.joblib", compress=3)
json.dump({"classes": labels}, open(f"{MODEL_DIR}/model_meta.json", "w"), indent=2)
print(f"\nsaved -> {MODEL_DIR}/log_type_clf.joblib")
