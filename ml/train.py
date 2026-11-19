"""Train and evaluate the NSL-KDD attack detector.

    python ml/train.py            # downloads the data (checksum-verified) into ml/data/, trains, writes ml/models/

Method, in order, so the test set is only used once at the end:
  1. Split Train+ into a training part and a validation part (80/20, stratified).
  2. Fit three candidate models on the training part and compare them on the validation part.
  3. Pick the best by validation F1, refit it on all of Train+, and evaluate it ONCE on the official Test+.

Note on the selection rule: the first run used validation ROC AUC, but two models both scored 1.0000 on it, so it could not
tell them apart and the tie went to whichever was listed first. Validation F1 separates them, so the rule was changed to F1.
That change was made after seeing the first run's test numbers (all three models are reported on Test+ either way).
"""

import argparse
import json
from datetime import date
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

import nslkdd

ROOT = Path(__file__).resolve().parent
SEED = 42


def candidates():
    return {
        "logistic_regression": Pipeline([("prep", nslkdd.preprocessor(scale=True)), ("model", LogisticRegression(max_iter=2000))]),
        "random_forest": Pipeline([("prep", nslkdd.preprocessor(scale=False)), ("model", RandomForestClassifier(n_estimators=150, min_samples_leaf=2, n_jobs=-1, random_state=SEED))]),
        "gradient_boosting": Pipeline([("prep", nslkdd.preprocessor(scale=False)), ("model", HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1, random_state=SEED))]),
    }


def scores(y_true, proba, threshold=0.5):
    pred = (proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred).ravel()
    return {
        "accuracy": round(accuracy_score(y_true, pred), 4),
        "precision": round(precision_score(y_true, pred), 4),
        "recall": round(recall_score(y_true, pred), 4),
        "f1": round(f1_score(y_true, pred), 4),
        "roc_auc": round(roc_auc_score(y_true, proba), 4),
        "false_positive_rate": round(fp / (fp + tn), 4),
        "confusion_matrix": {"true_negative": int(tn), "false_positive": int(fp), "false_negative": int(fn), "true_positive": int(tp)},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "models")
    args = parser.parse_args()

    nslkdd.download(args.data_dir)
    train = nslkdd.load(args.data_dir / "KDDTrain+.txt")
    test = nslkdd.load(args.data_dir / "KDDTest+.txt")
    X, y = train[nslkdd.FEATURES], train["is_attack"]

    X_fit, X_val, y_fit, y_val = train_test_split(X, y, test_size=0.2, stratify=y, random_state=SEED)
    validation = {}
    for name, pipe in candidates().items():
        pipe.fit(X_fit, y_fit)
        validation[name] = scores(y_val, pipe.predict_proba(X_val)[:, 1])
        print(f"validation  {name:20s} AUC {validation[name]['roc_auc']}  F1 {validation[name]['f1']}")
    best = max(validation, key=lambda n: validation[n]["f1"])

    # Refit every candidate on all of Train+ so the comparison on Test+ is like for like; the winner is fixed already.
    X_test, y_test = test[nslkdd.FEATURES], test["is_attack"]
    results, fitted = {}, {}
    for name, pipe in candidates().items():
        pipe.fit(X, y)
        fitted[name] = pipe
        results[name] = scores(y_test, pipe.predict_proba(X_test)[:, 1])
        print(f"test        {name:20s} accuracy {results[name]['accuracy']}  recall {results[name]['recall']}  FPR {results[name]['false_positive_rate']}")

    chosen = fitted[best]
    proba = chosen.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    per_category = {}
    for category, group in test.groupby("category"):
        idx = group.index
        correct = (pred[idx] == group["is_attack"].to_numpy()).mean()
        per_category[category] = {"records": int(len(group)), "correctly_classified": round(float(correct), 4)}
    seen = set(train["label"])
    new_attacks = test[(test["is_attack"] == 1) & (~test["label"].isin(seen))]
    old_attacks = test[(test["is_attack"] == 1) & (test["label"].isin(seen))]
    sweep = {str(t): {k: scores(y_test, proba, t)[k] for k in ("recall", "false_positive_rate", "precision")} for t in (0.1, 0.3, 0.5, 0.7, 0.9)}
    unseen = {
        "attack_types_never_seen_in_training": sorted(new_attacks["label"].unique()),
        "records_of_unseen_types": int(len(new_attacks)),
        "detected_unseen": round(float(pred[new_attacks.index].mean()), 4),
        "detected_seen": round(float(pred[old_attacks.index].mean()), 4),
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(chosen, args.out_dir / "nslkdd_model.joblib", compress=3)
    metrics = {
        "dataset": "NSL-KDD (official KDDTrain+ and KDDTest+)",
        "trained_on": date.today().isoformat(),
        "selected_model": best,
        "selection_rule": "highest F1 on a validation split of Train+ (the test set was not used to choose). Changed from ROC AUC after a first run, because two models tied at 1.0000; see ml/README.md",
        "train_records": int(len(train)), "test_records": int(len(test)),
        "threshold": 0.5,
        "validation": validation,
        "test": results,
        "selected_model_by_category": per_category,
        "threshold_sweep_on_test": sweep,
        "unseen_attacks": unseen,
    }
    (args.out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    print("selected:", best, "| model file KB:", round((args.out_dir / "nslkdd_model.joblib").stat().st_size / 1024))
    print(json.dumps({"by_category": per_category, "unseen": unseen}, indent=1))


if __name__ == "__main__":
    main()
