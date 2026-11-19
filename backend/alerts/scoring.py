"""Scores network connection records with the NSL-KDD attack model trained in ../ml."""

import io
import json
from functools import lru_cache

from django.conf import settings

# Same order as ml/nslkdd.py. A test checks that the two lists stay identical.
FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]
CATEGORICAL = ["protocol_type", "service", "flag"]


class RecordError(ValueError):
    """The uploaded records cannot be scored. The message is safe to show to the user."""


@lru_cache(maxsize=1)
def load_model():
    import joblib  # imported here so the rest of the API works even if the model stack is missing

    path = settings.ML_MODEL_DIR / "nslkdd_model.joblib"
    if not path.exists():
        raise FileNotFoundError(f"Model file not found at {path}")
    return joblib.load(path)


@lru_cache(maxsize=1)
def load_metrics():
    return json.loads((settings.ML_MODEL_DIR / "metrics.json").read_text())


def model_summary():
    """The numbers the dashboard shows. Everything here comes straight from ml/models/metrics.json."""
    m = load_metrics()
    chosen = m["selected_model"]
    return {
        "dataset": m["dataset"], "selected_model": chosen, "trained_on": m["trained_on"], "threshold": m["threshold"],
        "train_records": m["train_records"], "test_records": m["test_records"],
        "test": {k: v for k, v in m["test"][chosen].items()},
        "compared_on_test": {name: {k: r[k] for k in ("accuracy", "precision", "recall", "false_positive_rate")} for name, r in m["test"].items()},
        "by_category": m["selected_model_by_category"],
        "unseen_attacks": {k: m["unseen_attacks"][k] for k in ("records_of_unseen_types", "detected_unseen", "detected_seen")},
    }


def parse_records(text: str):
    """Reads CSV rows into a DataFrame with the 41 feature columns, or raises RecordError."""
    import pandas as pd

    try:
        frame = pd.read_csv(io.StringIO(text), header=None, dtype=str, skip_blank_lines=True, skipinitialspace=True)
    except Exception as error:
        raise RecordError(f"Could not read the data as CSV: {error}") from None
    if len(frame) == 0:
        raise RecordError("No records found.")
    if len(frame) > settings.MAX_CONNECTION_RECORDS:
        raise RecordError(f"Too many records ({len(frame)}). The limit is {settings.MAX_CONNECTION_RECORDS}.")
    width = frame.shape[1]
    if width not in (41, 43):
        raise RecordError(f"Each record needs 41 values (or 43 with the label and difficulty columns at the end); found {width}.")
    labels = None
    if width == 43:
        labels = frame.iloc[:, 41].str.strip().str.lower()
    frame = frame.iloc[:, :41]
    frame.columns = FEATURES
    for column in FEATURES:
        if column in CATEGORICAL:
            frame[column] = frame[column].str.strip()
            continue
        converted = pd.to_numeric(frame[column], errors="coerce")
        bad = converted.isna()
        if bad.any():
            row = int(bad.idxmax()) + 1
            raise RecordError(f"Record {row}: '{column}' must be a number, got '{frame[column].iloc[row - 1]}'.")
        frame[column] = converted
    for column in CATEGORICAL:
        if frame[column].isna().any() or (frame[column] == "").any():
            raise RecordError(f"'{column}' must not be empty.")
    return frame, labels


def score(frame):
    return load_model().predict_proba(frame[FEATURES])[:, 1]
