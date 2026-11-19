import json
import os
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import nslkdd  # noqa: E402

SAMPLE = ROOT / "sample" / "connections_sample.csv"
MODEL = ROOT / "models" / "nslkdd_model.joblib"
METRICS = ROOT / "models" / "metrics.json"


def test_feature_list_has_the_41_nsl_kdd_features_and_no_duplicates():
    assert len(nslkdd.FEATURES) == 41
    assert len(set(nslkdd.FEATURES)) == 41
    assert len(nslkdd.COLUMNS) == 43
    assert set(nslkdd.CATEGORICAL) <= set(nslkdd.FEATURES)


def test_every_attack_label_maps_to_one_of_four_categories():
    assert set(nslkdd.CATEGORY_OF.values()) == {"normal", "DoS", "Probe", "R2L", "U2R"}
    assert len(nslkdd.CATEGORY_OF) == 40  # 39 attack names across Train+ and Test+, plus "normal"


def test_sample_loads_and_is_labelled():
    frame = nslkdd.load(SAMPLE)
    assert len(frame) == 60
    assert frame["is_attack"].sum() == 30
    assert set(frame["category"]) == {"normal", "DoS", "Probe", "R2L", "U2R"}


def test_unknown_attack_labels_are_an_error(tmp_path):
    bad = pd.read_csv(SAMPLE, names=nslkdd.COLUMNS)
    bad.loc[0, "label"] = "brand_new_attack"
    path = tmp_path / "bad.txt"
    bad.to_csv(path, header=False, index=False)
    with pytest.raises(ValueError, match="brand_new_attack"):
        nslkdd.load(path)


def test_the_saved_model_scores_the_sample_sensibly():
    frame = nslkdd.load(SAMPLE)
    model = joblib.load(MODEL)
    proba = model.predict_proba(frame[nslkdd.FEATURES])[:, 1]
    assert proba.shape == (60,)
    assert ((proba >= 0) & (proba <= 1)).all()
    # On this sample the model should clearly separate the two groups on average.
    assert proba[frame["is_attack"] == 1].mean() > proba[frame["is_attack"] == 0].mean() + 0.3


def test_the_model_ignores_a_service_it_has_never_seen():
    frame = nslkdd.load(SAMPLE).head(3).copy()
    frame["service"] = "totally_new_service"
    proba = joblib.load(MODEL).predict_proba(frame[nslkdd.FEATURES])[:, 1]
    assert np.isfinite(proba).all()


@pytest.mark.skipif(not os.environ.get("NSLKDD_DOWNLOAD"), reason="set NSLKDD_DOWNLOAD=1 to download Test+ and re-check the reported numbers")
def test_the_published_metrics_can_be_reproduced(tmp_path):
    """Loads the committed model, scores the official Test+ file and compares with metrics.json."""
    from sklearn.metrics import accuracy_score, recall_score

    nslkdd.download(tmp_path)
    test = nslkdd.load(tmp_path / "KDDTest+.txt")
    model = joblib.load(MODEL)
    pred = (model.predict_proba(test[nslkdd.FEATURES])[:, 1] >= 0.5).astype(int)
    reported = json.loads(METRICS.read_text())["test"][json.loads(METRICS.read_text())["selected_model"]]
    assert round(accuracy_score(test["is_attack"], pred), 4) == reported["accuracy"]
    assert round(recall_score(test["is_attack"], pred), 4) == reported["recall"]
