"""The NSL-KDD dataset: loading, labels and the feature pipeline.

NSL-KDD is a cleaned-up version of the KDD Cup 1999 network intrusion data (duplicates removed).
Each row describes one network connection with 41 features and a label (normal or a named attack).
The official Train+ and Test+ files are used as they are. Test+ deliberately contains 17 attack types
that never appear in Train+, which makes it a fair check of how a model copes with new attacks.
"""

import hashlib
import urllib.request
from pathlib import Path

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler

BASE_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/"
FILES = {
    "KDDTrain+.txt": "1b86d2f957b33082081bba410fe129b475efebcc13c9014c3f447c8271aadf95",
    "KDDTest+.txt": "fa46b0935342616aa83b7c2578db355b6a7aaabbc492248172c7a1e8b7ab8f84",
}

CATEGORICAL = ["protocol_type", "service", "flag"]
FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]
NUMERIC = [c for c in FEATURES if c not in CATEGORICAL]
COLUMNS = FEATURES + ["label", "difficulty"]

CATEGORY_OF = {
    **dict.fromkeys(["back", "land", "neptune", "pod", "smurf", "teardrop", "apache2", "udpstorm", "processtable", "worm", "mailbomb"], "DoS"),
    **dict.fromkeys(["ipsweep", "nmap", "portsweep", "satan", "mscan", "saint"], "Probe"),
    **dict.fromkeys(["ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy", "warezclient", "warezmaster", "sendmail", "named",
                     "snmpgetattack", "snmpguess", "xlock", "xsnoop", "httptunnel"], "R2L"),
    **dict.fromkeys(["buffer_overflow", "loadmodule", "perl", "rootkit", "ps", "sqlattack", "xterm"], "U2R"),
    "normal": "normal",
}


def download(data_dir: Path) -> None:
    """Fetches the official files and refuses anything whose SHA-256 does not match."""
    data_dir.mkdir(parents=True, exist_ok=True)
    for name, expected in FILES.items():
        target = data_dir / name
        if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == expected:
            continue
        with urllib.request.urlopen(BASE_URL + urllib.request.quote(name), timeout=120) as response:
            blob = response.read()
        if hashlib.sha256(blob).hexdigest() != expected:
            raise RuntimeError(f"{name} does not match the expected checksum; refusing to use it.")
        target.write_bytes(blob)


def load(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path, names=COLUMNS)
    frame["is_attack"] = (frame["label"] != "normal").astype(int)
    frame["category"] = frame["label"].map(CATEGORY_OF)
    if frame["category"].isna().any():
        unknown = sorted(frame.loc[frame["category"].isna(), "label"].unique())
        raise ValueError(f"Unmapped attack labels: {unknown}")
    return frame


def preprocessor(scale: bool) -> ColumnTransformer:
    """One-hot encodes the three text columns. Scaling is only needed by the linear model."""
    return ColumnTransformer(
        [
            ("categories", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL),
            ("numbers", StandardScaler() if scale else "passthrough", NUMERIC),
        ]
    )
