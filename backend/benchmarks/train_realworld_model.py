import joblib
from pathlib import Path
from datasets import load_dataset
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, f1_score

print("1. Downloading real-world threat datasets from Hugging Face...")
train_texts, train_labels = [], []
test_texts, test_labels = [], []

# Dataset 1: xTRam1/safe-guard-prompt-injection (8,100+ benign + adversarial samples)
ds_safeguard = load_dataset("xTRam1/safe-guard-prompt-injection")
for row in ds_safeguard["train"]:
    train_texts.append(row["text"])
    train_labels.append(int(row["label"]))
for row in ds_safeguard["test"]:
    test_texts.append(row["text"])
    test_labels.append(int(row["label"]))

# Dataset 2: deepset/prompt-injections (human-authored multilingual & roleplay injections)
ds_deepset = load_dataset("deepset/prompt-injections")
for row in ds_deepset["train"]:
    train_texts.append(row["text"])
    train_labels.append(int(row["label"]))
for row in ds_deepset["test"]:
    test_texts.append(row["text"])
    test_labels.append(int(row["label"]))

# Dataset 3: Lakera/gandalf_ignore_instructions (real red-team Gandalf attacks)
ds_gandalf = load_dataset("Lakera/gandalf_ignore_instructions")
for row in ds_gandalf["train"]:
    train_texts.append(row["text"])
    train_labels.append(1)
for row in ds_gandalf["test"]:
    test_texts.append(row["text"])
    test_labels.append(1)

print(f"Loaded {len(train_texts)} training samples and {len(test_texts)} unseen test samples.")

# Hybrid word + character n-gram features catch both semantic phrasing and obfuscated/scrambled words
vectorizer = FeatureUnion([
    ("word", TfidfVectorizer(ngram_range=(1, 3), max_features=35000, sublinear_tf=True)),
    ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=35000, sublinear_tf=True)),
])

print("2. Extracting n-gram features & training calibrated threat classifier...")
X_train = vectorizer.fit_transform(train_texts)
X_test = vectorizer.transform(test_texts)

base_clf = LogisticRegression(C=3.0, max_iter=1000, class_weight="balanced")
clf = CalibratedClassifierCV(base_clf, cv=3)
clf.fit(X_train, train_labels)

preds = clf.predict(X_test)
f1 = f1_score(test_labels, preds)
print(f"\n3. Held-Out Unseen Test F1-Score: {f1:.4f}")
print(classification_report(test_labels, preds, target_names=["Benign", "Attack"]))

out_path = Path("models/attroxx_threat_clf.joblib")
joblib.dump({"vectorizer": vectorizer, "classifier": clf}, out_path)
print(f"Saved trained real-world threat model to {out_path.resolve()}")
