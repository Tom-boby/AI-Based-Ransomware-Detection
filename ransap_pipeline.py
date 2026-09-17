"""
CARI RanSAP Pipeline
====================
Reads RanSAP ATA-write behavioral logs, extracts per-run features,
trains RF / XGBoost / Autoencoder, fuses them, and saves
all results to models/ransap/ for the dashboard.

Run this script ONCE after placing the CSV files:
  .venv\\Scripts\\python.exe ransap_pipeline.py

The dashboard reads models/ransap/results.json automatically.
"""

import os, sys, json, gc, time, warnings, pathlib, collections
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
)
from sklearn.utils.class_weight import compute_class_weight
import joblib
import shap

warnings.filterwarnings("ignore")

# ─── Paths ────────────────────────────────────────────────────────────────────
PROJECT_ROOT = pathlib.Path(__file__).parent
DATA_DIR     = PROJECT_ROOT / "data" / "ransap"
MODEL_DIR    = PROJECT_ROOT / "models" / "ransap"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# ─── Family → label mapping ───────────────────────────────────────────────────
LABEL_MAP = {
    "AESCrypt"            : 1,
    "Cerber-w10dirs"      : 1,
    "Darkside-w10dirs"    : 1,
    "Ryuk-w10dirs"        : 1,
    "Sodinokibi-w10dirs"  : 1,
    "TeslaCrypt-w10dirs"  : 1,
    "WannaCry-w10dirs"    : 1,
    "Excel"               : 0,
    "Firefox"             : 0,
    "Zip"                 : 0,
}

# ─── Friendly family name ─────────────────────────────────────────────────────
FRIENDLY = {
    "AESCrypt"           : "AESCrypt",
    "Cerber-w10dirs"     : "Cerber",
    "Darkside-w10dirs"   : "DarkSide",
    "Ryuk-w10dirs"       : "Ryuk",
    "Sodinokibi-w10dirs" : "Sodinokibi (REvil)",
    "TeslaCrypt-w10dirs" : "TeslaCrypt",
    "WannaCry-w10dirs"   : "WannaCry",
    "Excel"              : "Excel (Benign)",
    "Firefox"            : "Firefox (Benign)",
    "Zip"                : "7-Zip (Benign)",
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. Discover CSV files
# ─────────────────────────────────────────────────────────────────────────────
def discover_runs(data_dir: pathlib.Path):
    """Walk data/ransap/ and return list of (family, run_id, csv_path, label)."""
    runs = []
    for family_dir in sorted(data_dir.iterdir()):
        if not family_dir.is_dir():
            continue
        family = family_dir.name
        label  = LABEL_MAP.get(family)
        if label is None:
            print(f"  [WARN] Unknown family '{family}' — skipping")
            continue
        for run_dir in sorted(family_dir.iterdir()):
            if not run_dir.is_dir():
                continue
            for csv_name in ("ata_write.csv", "ata_read.csv"):
                csv_path = run_dir / csv_name
                if csv_path.exists():
                    runs.append({
                        "family"  : family,
                        "run_id"  : run_dir.name,
                        "csv_path": csv_path,
                        "csv_type": csv_name.replace(".csv",""),
                        "label"   : label,
                    })
    return runs

# ─────────────────────────────────────────────────────────────────────────────
# 2. Inspect CSV schema (print on first run)
# ─────────────────────────────────────────────────────────────────────────────
def inspect_schema(csv_path: pathlib.Path, n_rows: int = 5000):
    """Read n_rows to infer schema without loading entire file."""
    df = pd.read_csv(csv_path, nrows=n_rows, low_memory=False)
    return df

def print_schema(df: pd.DataFrame, path: pathlib.Path):
    print(f"\n{'='*60}")
    print(f"Schema: {path.name}  (from {path.parent.parent.name}/{path.parent.name})")
    print(f"Columns ({len(df.columns)}): {list(df.columns)}")
    print(f"Dtypes:\n{df.dtypes}")
    print(f"Sample rows:\n{df.head(3)}")
    print(f"Null counts:\n{df.isnull().sum()}")
    print(f"{'='*60}\n")

# ─────────────────────────────────────────────────────────────────────────────
# 3. Feature extraction
# ─────────────────────────────────────────────────────────────────────────────
def _shannon_entropy(series: pd.Series) -> float:
    counts = series.value_counts(normalize=True)
    return float(-(counts * np.log2(counts + 1e-12)).sum())

def extract_features(csv_path: pathlib.Path, col_map: dict) -> dict:
    """
    Stream-read a RanSAP CSV and extract a fixed behavioral feature vector.
    col_map: dict with keys 'timestamp','lba','size' mapped to actual col names.
    Returns a dict of scalar features.
    """
    CHUNK = 200_000
    # accumulators
    n_ops      = 0
    total_bytes= 0.0
    sizes      = []
    lbas       = []
    ts_vals    = []

    reader = pd.read_csv(csv_path, chunksize=CHUNK, low_memory=False)
    for chunk in reader:
        chunk.columns = [c.strip().lower() for c in chunk.columns]
        # map columns
        sz_col = col_map.get('size')
        lb_col = col_map.get('lba')
        ts_col = col_map.get('timestamp')

        n_ops += len(chunk)

        if sz_col and sz_col in chunk.columns:
            s = pd.to_numeric(chunk[sz_col], errors='coerce').dropna()
            total_bytes += float(s.sum())
            sizes.extend(s.sample(min(len(s), 2000), random_state=42).tolist())

        if lb_col and lb_col in chunk.columns:
            l = pd.to_numeric(chunk[lb_col], errors='coerce').dropna()
            lbas.extend(l.sample(min(len(l), 2000), random_state=42).tolist())

        if ts_col and ts_col in chunk.columns:
            t = pd.to_numeric(chunk[ts_col], errors='coerce').dropna()
            ts_vals.extend(t.sample(min(len(t), 2000), random_state=42).tolist())

        del chunk

    sizes  = np.array(sizes,  dtype=np.float64)
    lbas   = np.array(lbas,   dtype=np.float64)
    ts_arr = np.array(ts_vals, dtype=np.float64)

    feats = {}
    feats['total_ops']     = n_ops
    feats['total_bytes']   = total_bytes
    feats['mean_size']     = float(np.mean(sizes))  if len(sizes)  > 0 else 0.0
    feats['std_size']      = float(np.std(sizes))   if len(sizes)  > 1 else 0.0
    feats['max_size']      = float(np.max(sizes))   if len(sizes)  > 0 else 0.0
    feats['median_size']   = float(np.median(sizes)) if len(sizes) > 0 else 0.0

    if len(lbas) > 1:
        feats['mean_lba']      = float(np.mean(lbas))
        feats['std_lba']       = float(np.std(lbas))
        feats['lba_range']     = float(np.max(lbas) - np.min(lbas))
        sorted_lba = np.sort(lbas)
        diffs = np.diff(sorted_lba)
        feats['sequential_ratio'] = float(np.mean(diffs >= 0) if len(diffs) > 0 else 0.0)
        feats['unique_lba_ratio'] = float(len(np.unique(lbas)) / len(lbas)) if len(lbas) > 0 else 0.0
    else:
        for k in ['mean_lba','std_lba','lba_range','sequential_ratio','unique_lba_ratio']:
            feats[k] = 0.0

    if len(ts_arr) > 1:
        duration = float(np.max(ts_arr) - np.min(ts_arr))
        feats['duration']    = max(duration, 1e-6)
        feats['ops_per_sec'] = n_ops / feats['duration']
        # burst: gaps > median_gap * 5
        ts_sorted = np.sort(ts_arr)
        gaps = np.diff(ts_sorted)
        if len(gaps) > 0:
            med_gap = np.median(gaps)
            feats['burst_count'] = int(np.sum(gaps > max(med_gap * 5, 1e-6)))
        else:
            feats['burst_count'] = 0
    else:
        feats['duration']    = 1.0
        feats['ops_per_sec'] = 0.0
        feats['burst_count'] = 0

    # Entropy of sizes
    if len(sizes) > 1:
        bins = np.histogram(sizes, bins=min(20, max(2, int(np.sqrt(len(sizes))))))[0]
        bins = bins / (bins.sum() + 1e-12)
        feats['size_entropy'] = float(-np.sum(bins * np.log2(bins + 1e-12)))
    else:
        feats['size_entropy'] = 0.0

    feats['bytes_per_op'] = total_bytes / max(n_ops, 1)

    return feats

# ─────────────────────────────────────────────────────────────────────────────
# 4. Auto-detect column mapping from a sample
# ─────────────────────────────────────────────────────────────────────────────
def detect_col_map(csv_path: pathlib.Path) -> dict:
    """Peek at the first 100 rows, auto-detect timestamp/lba/size columns."""
    df = pd.read_csv(csv_path, nrows=100, low_memory=False)
    df.columns = [c.strip().lower() for c in df.columns]
    cols = list(df.columns)

    # Heuristic matching
    def find_col(candidates):
        for c in candidates:
            if c in cols:
                return c
        # partial match
        for c in cols:
            for cand in candidates:
                if cand in c:
                    return c
        return None

    ts_col   = find_col(['timestamp','time','ts','nanosecond','nano','usec','msec','sec'])
    lba_col  = find_col(['lba','sector','offset','block','addr','address'])
    sz_col   = find_col(['size','len','length','bytes','transfer'])

    col_map = {
        'timestamp': ts_col,
        'lba'      : lba_col,
        'size'     : sz_col,
    }
    return col_map, df, cols

# ─────────────────────────────────────────────────────────────────────────────
# 5. Build feature matrix
# ─────────────────────────────────────────────────────────────────────────────
def build_dataset(runs: list, schema_printed: set) -> pd.DataFrame:
    records = []
    col_map_cache = {}

    for info in runs:
        csv_path = info['csv_path']
        family   = info['family']

        # Detect column map (once per CSV type)
        cache_key = info['csv_type']
        if cache_key not in col_map_cache:
            col_map, sample_df, raw_cols = detect_col_map(csv_path)
            col_map_cache[cache_key] = col_map
            key = f"{family}/{info['run_id']}/{info['csv_type']}"
            if key not in schema_printed:
                print(f"\n[SCHEMA] {key}")
                print(f"  Raw columns: {raw_cols}")
                print(f"  Detected col_map: {col_map}")
                print(f"  Sample:\n{sample_df.head(3).to_string()}")
                schema_printed.add(key)
        else:
            col_map = col_map_cache[cache_key]

        print(f"  Extracting features: {family}/{info['run_id']}/{info['csv_type']}...", end=" ", flush=True)
        t0 = time.perf_counter()
        try:
            feats = extract_features(csv_path, col_map)
        except Exception as e:
            print(f"ERROR: {e}")
            continue
        elapsed = time.perf_counter() - t0
        print(f"{elapsed:.1f}s  ops={feats['total_ops']:,}  bytes={feats['total_bytes']/1e6:.1f}MB")

        row = {
            'family'  : family,
            'run_id'  : info['run_id'],
            'csv_type': info['csv_type'],
            'label'   : info['label'],
            **feats
        }
        records.append(row)
        gc.collect()

    return pd.DataFrame(records)

# ─────────────────────────────────────────────────────────────────────────────
# 6. Aggregate read+write features per run (if both available)
# ─────────────────────────────────────────────────────────────────────────────
def aggregate_run_features(df: pd.DataFrame) -> pd.DataFrame:
    """If both ata_read and ata_write are present, combine into one row per run."""
    FEAT_COLS = [c for c in df.columns if c not in ('family','run_id','csv_type','label')]

    write_df = df[df['csv_type']=='ata_write'].copy().drop(columns=['csv_type'])
    read_df  = df[df['csv_type']=='ata_read'].copy().drop(columns=['csv_type'])

    if read_df.empty:
        return write_df.rename(columns={c: f'w_{c}' for c in FEAT_COLS})

    write_df = write_df.rename(columns={c: f'w_{c}' for c in FEAT_COLS})
    read_df  = read_df.rename(columns={c: f'r_{c}' for c in FEAT_COLS})

    merged = pd.merge(write_df, read_df, on=['family','run_id','label'], how='outer')

    # Add ratio features
    for c in FEAT_COLS:
        w_col = f'w_{c}'
        r_col = f'r_{c}'
        if w_col in merged.columns and r_col in merged.columns:
            merged[f'rw_ratio_{c}'] = (
                merged[r_col] / (merged[w_col] + 1e-12)
            )

    merged.fillna(0.0, inplace=True)
    return merged

# ─────────────────────────────────────────────────────────────────────────────
# 7. Autoencoder anomaly detector (sklearn-compatible, no TF needed)
# ─────────────────────────────────────────────────────────────────────────────
class NumpyAutoencoder:
    """Tiny 3-layer autoencoder in pure NumPy — no TF/Keras dependency."""
    def __init__(self, input_dim: int, encoding_dim: int = 4, lr: float = 0.01, epochs: int = 200):
        self.input_dim    = input_dim
        self.encoding_dim = encoding_dim
        self.lr           = lr
        self.epochs       = epochs
        self.threshold_   = None
        self._init_weights()

    def _init_weights(self):
        rng = np.random.RandomState(42)
        h = max(8, self.input_dim // 2)
        self.W1 = rng.randn(self.input_dim, h) * 0.1
        self.b1 = np.zeros(h)
        self.W2 = rng.randn(h, self.encoding_dim) * 0.1
        self.b2 = np.zeros(self.encoding_dim)
        self.W3 = rng.randn(self.encoding_dim, h) * 0.1
        self.b3 = np.zeros(h)
        self.W4 = rng.randn(h, self.input_dim) * 0.1
        self.b4 = np.zeros(self.input_dim)

    @staticmethod
    def _relu(x): return np.maximum(0, x)
    @staticmethod
    def _relu_d(x): return (x > 0).astype(float)

    def _forward(self, X):
        h1 = self._relu(X @ self.W1 + self.b1)
        h2 = self._relu(h1 @ self.W2 + self.b2)
        h3 = self._relu(h2 @ self.W3 + self.b3)
        out = h3 @ self.W4 + self.b4
        return h1, h2, h3, out

    def fit(self, X_train: np.ndarray):
        X = X_train.copy()
        for ep in range(self.epochs):
            # Forward
            h1, h2, h3, out = self._forward(X)
            # MSE loss
            diff = out - X
            # Backward (simple gradient descent)
            dout = 2 * diff / len(X)
            dW4 = h3.T @ dout;        db4 = dout.sum(0)
            dh3 = dout @ self.W4.T * self._relu_d(h3 @ self.W3.T + self.b3)
            # clip to prevent explosion
            dh3 = np.clip(dh3, -1, 1)
            dW3 = h2.T @ dh3;         db3 = dh3.sum(0)
            dh2 = dh3 @ self.W3.T * self._relu_d(h2 @ self.W2.T + self.b2)
            dh2 = np.clip(dh2, -1, 1)
            dW2 = h1.T @ dh2;         db2 = dh2.sum(0)
            dh1 = dh2 @ self.W2.T * self._relu_d(h1 @ self.W1.T + self.b1)
            dh1 = np.clip(dh1, -1, 1)
            dW1 = X.T @ dh1;          db1 = dh1.sum(0)
            # Update
            self.W4 -= self.lr * dW4; self.b4 -= self.lr * db4
            self.W3 -= self.lr * dW3; self.b3 -= self.lr * db3
            self.W2 -= self.lr * dW2; self.b2 -= self.lr * db2
            self.W1 -= self.lr * dW1; self.b1 -= self.lr * db1
        # Set threshold: 95th percentile of training reconstruction error
        _, _, _, out = self._forward(X)
        errs = np.mean((out - X)**2, axis=1)
        self.threshold_ = float(np.percentile(errs, 95))
        return self

    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        _, _, _, out = self._forward(X)
        return np.mean((out - X)**2, axis=1)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return anomaly probability in [0,1] via sigmoid-scaled reconstruction error."""
        errs = self.reconstruction_error(X)
        # Normalize by threshold
        scores = errs / (self.threshold_ + 1e-10)
        proba  = 1 / (1 + np.exp(-4 * (scores - 1)))   # sigmoid centred at threshold
        return proba

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X) >= 0.5).astype(int)

# ─────────────────────────────────────────────────────────────────────────────
# 8. Evaluation helper
# ─────────────────────────────────────────────────────────────────────────────
def evaluate_model(name, y_true, y_pred, y_proba=None):
    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    cm   = confusion_matrix(y_true, y_pred).tolist()
    tp   = sum(1 for a,b in zip(y_true,y_pred) if a==1 and b==1)
    fn   = sum(1 for a,b in zip(y_true,y_pred) if a==1 and b==0)
    fnr  = fn / (tp + fn + 1e-9)
    auc  = roc_auc_score(y_true, y_proba) if y_proba is not None and len(set(y_true))>1 else 0.5

    print(f"\n--- {name} ---")
    print(f"  Accuracy:  {acc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall:    {rec:.4f}")
    print(f"  F1-Score:  {f1:.4f}")
    print(f"  FNR:       {fnr:.4f}")
    print(f"  ROC-AUC:   {auc:.4f}")
    print(f"  Confusion matrix: {cm}")

    return {
        "accuracy": round(acc,4), "precision": round(prec,4),
        "recall":   round(rec,4), "f1":        round(f1,4),
        "fnr":      round(fnr,4), "roc_auc":   round(auc,4),
        "confusion_matrix": cm,
    }

# ─────────────────────────────────────────────────────────────────────────────
# 9. Main pipeline
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("\n" + "="*60)
    print("  CARI — RanSAP Storage-Behavioral Pipeline")
    print("="*60)

    # ── Discover runs ──────────────────────────────────────────
    runs = discover_runs(DATA_DIR)
    if not runs:
        print(f"\n[ERROR] No CSV files found in {DATA_DIR}")
        print("  Please download the RanSAP files as instructed in")
        print("  DOWNLOAD_INSTRUCTIONS.md and place them in data/ransap/")
        sys.exit(1)

    print(f"\nFound {len(runs)} CSV file(s):")
    for r in runs:
        print(f"  [{r['label']}] {r['family']}/{r['run_id']}/{r['csv_type']}")

    # ── Build feature matrix ───────────────────────────────────
    print("\n[1/5] Extracting behavioral features...")
    schema_printed = set()
    raw_df = build_dataset(runs, schema_printed)
    print(f"\nRaw feature rows: {len(raw_df)}")
    print(raw_df[['family','run_id','csv_type','label','total_ops','total_bytes','ops_per_sec']].to_string())

    # ── Aggregate read+write per run ───────────────────────────
    print("\n[2/5] Aggregating per-run features...")
    agg_df = aggregate_run_features(raw_df)
    print(f"Aggregated rows: {len(agg_df)}")

    FEAT_COLS = [c for c in agg_df.columns if c not in ('family','run_id','label')]
    X = agg_df[FEAT_COLS].values.astype(np.float32)
    y = agg_df['label'].values.astype(int)

    print(f"Feature matrix: {X.shape}  |  Classes: {collections.Counter(y)}")

    # Replace inf/nan
    X = np.where(np.isfinite(X), X, 0.0).astype(np.float32)

    # ── Train/Val/Test split (stratified, leave-one-run-out safe) ──
    print("\n[3/5] Splitting data...")
    from sklearn.model_selection import train_test_split
    n = len(X)
    if n < 6:
        print(f"[WARN] Only {n} runs found — need at least 6 for train/test split.")
        print("       Add more CSV files for a meaningful evaluation.")
        # Still proceed with leave-one-out CV
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=max(1, n//3), random_state=42, stratify=y if len(set(y))>1 else None
        )
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y
        )
    print(f"  Train: {len(X_train)}  Test: {len(X_test)}")

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train).astype(np.float32)
    X_test_s  = scaler.transform(X_test).astype(np.float32)

    results = {}

    # ── Random Forest ───────────────────────────────────────────
    print("\n[4a/5] Training Random Forest...")
    cw = None
    if len(set(y_train)) > 1:
        weights = compute_class_weight("balanced", classes=np.unique(y_train), y=y_train)
        cw = dict(zip(np.unique(y_train), weights))
    rf = RandomForestClassifier(n_estimators=200, class_weight=cw, random_state=42, n_jobs=-1)
    rf.fit(X_train_s, y_train)
    rf_pred  = rf.predict(X_test_s)
    rf_proba = rf.predict_proba(X_test_s)[:,1]
    results["Random Forest"] = evaluate_model("Random Forest", y_test, rf_pred, rf_proba)

    # Feature importances
    importances = pd.Series(rf.feature_importances_, index=FEAT_COLS).sort_values(ascending=False)
    top_feats = importances.head(12).to_dict()
    results["Random Forest"]["top_features"] = [
        {"feature": k, "importance": round(float(v), 6)} for k, v in top_feats.items()
    ]

    # SHAP
    print("  Computing SHAP values...")
    try:
        explainer   = shap.TreeExplainer(rf)
        shap_values = explainer.shap_values(X_test_s)
        sv = shap_values[1] if isinstance(shap_values, list) else shap_values
        mean_abs_shap = np.abs(sv).mean(axis=0)
        shap_feat_importance = dict(zip(FEAT_COLS, mean_abs_shap.tolist()))
        results["Random Forest"]["shap_importance"] = [
            {"feature": k, "shap": round(float(v), 6)}
            for k, v in sorted(shap_feat_importance.items(), key=lambda x: -x[1])[:12]
        ]
    except Exception as e:
        print(f"  [WARN] SHAP failed: {e}")
        results["Random Forest"]["shap_importance"] = results["Random Forest"]["top_features"]

    # ── XGBoost ─────────────────────────────────────────────────
    print("\n[4b/5] Training XGBoost...")
    try:
        from xgboost import XGBClassifier
        scale_pos = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
        xgb = XGBClassifier(
            n_estimators=200, max_depth=4, learning_rate=0.05,
            scale_pos_weight=scale_pos, eval_metric='logloss',
            random_state=42, n_jobs=-1, verbosity=0,
        )
        xgb.fit(X_train_s, y_train)
        xgb_pred  = xgb.predict(X_test_s)
        xgb_proba = xgb.predict_proba(X_test_s)[:,1]
        results["XGBoost"] = evaluate_model("XGBoost", y_test, xgb_pred, xgb_proba)
        xgb_imp = pd.Series(xgb.feature_importances_, index=FEAT_COLS).sort_values(ascending=False)
        results["XGBoost"]["top_features"] = [
            {"feature": k, "importance": round(float(v),6)} for k,v in xgb_imp.head(12).items()
        ]
    except ImportError:
        print("  [WARN] XGBoost not available — skipping")
        xgb_proba = rf_proba.copy()
        results["XGBoost"] = results["Random Forest"].copy()

    # ── Autoencoder (benign-only training) ─────────────────────
    print("\n[4c/5] Training Autoencoder (anomaly detector)...")
    benign_mask = (y_train == 0)
    if benign_mask.sum() > 0:
        X_benign = X_train_s[benign_mask]
        ae = NumpyAutoencoder(input_dim=X_train_s.shape[1], encoding_dim=max(2, X_train_s.shape[1]//3), epochs=300)
        ae.fit(X_benign)
        ae_proba = ae.predict_proba(X_test_s)
        ae_pred  = ae.predict(X_test_s)
        results["Autoencoder"] = evaluate_model("Autoencoder", y_test, ae_pred, ae_proba)
    else:
        print("  [WARN] No benign training samples — skipping autoencoder")
        ae_proba = np.zeros(len(y_test))
        ae_pred  = np.zeros(len(y_test), dtype=int)
        results["Autoencoder"] = evaluate_model("Autoencoder", y_test, ae_pred, None)

    # ── CARI Fusion ────────────────────────────────────────────
    print("\n[4d/5] CARI Fusion (AUC-weighted ensemble)...")
    auc_weights = []
    proba_list  = []
    for name, proba in [("RF", rf_proba), ("XGB", xgb_proba), ("AE", ae_proba)]:
        if len(set(y_test)) > 1:
            try:
                a = roc_auc_score(y_test, proba)
            except:
                a = 0.5
        else:
            a = 0.5
        w = max(0.0, a - 0.5)
        auc_weights.append(w)
        proba_list.append(proba)

    total_w = sum(auc_weights) + 1e-12
    fused_proba = sum(w/total_w * p for w,p in zip(auc_weights, proba_list))
    fused_pred  = (fused_proba >= 0.5).astype(int)
    results["CARI Fused"] = evaluate_model("CARI Fused", y_test, fused_pred, fused_proba)

    # ── Save everything ────────────────────────────────────────
    print("\n[5/5] Saving models and results...")
    joblib.dump(rf,     MODEL_DIR / "rf_model.joblib")
    joblib.dump(scaler, MODEL_DIR / "scaler.joblib")
    try:
        joblib.dump(xgb, MODEL_DIR / "xgb_model.joblib")
    except:
        pass
    joblib.dump(ae,     MODEL_DIR / "autoencoder.joblib")

    # Dataset stats
    family_counts = agg_df.groupby(['family','label']).size().reset_index(name='count')
    dataset_info = {
        "total_runs"     : len(agg_df),
        "ransomware_runs": int((y == 1).sum()),
        "benign_runs"    : int((y == 0).sum()),
        "n_features"     : len(FEAT_COLS),
        "feature_names"  : FEAT_COLS,
        "families"       : {
            FRIENDLY.get(row['family'], row['family']): {
                "count": int(row['count']),
                "label": int(row['label'])
            }
            for _, row in family_counts.iterrows()
        },
        "train_runs"     : int(len(X_train)),
        "test_runs"      : int(len(X_test)),
    }

    output = {
        "dataset"       : dataset_info,
        "models"        : results,
        "feature_names" : FEAT_COLS,
    }

    with open(MODEL_DIR / "results.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n  Saved to {MODEL_DIR}/")
    print("\n" + "="*60)
    print("  Pipeline complete!")
    print("  Start dashboard: .venv\\Scripts\\python.exe dashboard.py")
    print("  Open: http://localhost:8000")
    print("="*60 + "\n")
    return output

if __name__ == "__main__":
    main()
