# ThreatLens ML: network attack detection on NSL-KDD

A classifier that decides whether a network connection looks normal or like an attack, trained and evaluated on the public **NSL-KDD** benchmark. This folder holds the training code, the trained model and the full evaluation, including where it fails.

## The data

NSL-KDD is a cleaned-up version of the 1999 KDD Cup intrusion data: each row is one network connection with 41 features (duration, protocol, service, byte counts, error rates and so on) and a label, either `normal` or one of 39 named attacks grouped into four families (DoS, Probe, R2L, U2R).

I use the **official split without changing it**: `KDDTrain+` (125,973 connections) to train and `KDDTest+` (22,544) to test. The test file deliberately contains **17 attack types that never appear in training**, so it checks how the model copes with attacks it has not seen. The download script verifies SHA-256 checksums and refuses a file that does not match.

## Method

1. Hold out 20% of the training file as a validation set.
2. Fit three models on the rest and compare them on the validation set: logistic regression (a baseline), a random forest, and gradient boosting.
3. Pick the best by validation F1, refit it on all of the training file, and score it on the official test file **once**.

All three models are also scored on the test file so you can see the whole picture, but the test set was not used to choose between them.

**A disclosure about step 3.** My first run chose by validation ROC AUC. Two models tied at 1.0000, so the choice was arbitrary (it went to the random forest). Validation F1 separates them, so I switched to it. I made that change after seeing the first run's test results, so treat the model choice with that in mind. Gradient boosting is also the better model on the test file, which is the more honest reason to trust it, but you should know the order things happened in.

## Results on the official test file (22,544 connections)

| Model | Accuracy | Precision | Recall | False-alarm rate |
| --- | --- | --- | --- | --- |
| Logistic regression (baseline) | 75.4% | 91.8% | 62.4% | 7.4% |
| Random forest | 76.6% | 96.8% | 60.9% | 2.7% |
| **Gradient boosting (chosen)** | **80.3%** | **96.9%** | **67.6%** | **2.8%** |

In plain words, for the chosen model: when it says "attack" it is right 97% of the time, and it raises a false alarm on about 3 in 100 normal connections, **but it misses about a third of the attacks**.

Validation scores were far higher (F1 0.999) than test scores (0.80). That gap is the point of the test file: a random split of the training data shares attack types with training, the official test file does not.

### Where it works and where it does not

| Family | Test records | Classified correctly |
| --- | --- | --- |
| Normal | 9,711 | 97.2% |
| DoS (denial of service) | 7,460 | 87.1% |
| Probe (scanning) | 2,421 | 76.5% |
| R2L (remote-to-local, e.g. password guessing) | 2,885 | **10.6%** |
| U2R (privilege escalation) | 67 | **19.4%** |

- Attack types it saw in training are detected 78.7% of the time. Attack types it **never** saw are detected 40.6% of the time.
- It is strong on noisy, high-volume attacks (floods and scans) and weak on quiet ones that look like ordinary sessions (R2L and U2R). Those are exactly the attacks that matter most to a defender, so this model should **add** to rules and human review, not replace them.
- Moving the decision threshold changes little: from 0.1 to 0.9, recall moves between 72% and 62% while the false-alarm rate stays near 2.8%. The full sweep is in `models/metrics.json`.

## Limits you should know about

- NSL-KDD is old (1999 traffic, simulated in a lab). Its numbers say little about how this would perform on a modern network.
- The features are connection statistics produced by a specific tool. This model cannot read raw packets or SSH logs; the SSH rules in ThreatLens cover those separately.
- The trained model is a scikit-learn pipeline saved with joblib, which is a pickle file. Only load model files you produced yourself or trust.

## Run it

```bash
cd ml
pip install -r requirements.txt
python train.py          # downloads the data (about 22 MB, checksum-verified), trains, writes models/
python -m pytest tests   # 7 tests; set NSLKDD_DOWNLOAD=1 to also re-check the published numbers against the test file
```

`sample/connections_sample.csv` has 60 real connections from the test file (30 normal, 30 attacks) for trying the model without downloading anything.

## Files

| File | Purpose |
| --- | --- |
| `nslkdd.py` | data download and loading, label families, feature pipeline |
| `train.py` | the experiment above |
| `models/nslkdd_model.joblib` | the trained model (about 260 KB) |
| `models/metrics.json` | every number in this document |
| `tests/test_ml.py` | label coverage, sample loading, model sanity, and reproduction of the published metrics |
