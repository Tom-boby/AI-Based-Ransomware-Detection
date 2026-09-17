"""
CARI — EMBER Dashboard Backend
Supports two modes:
  LIVE MODE:  models/ember/ has rf_model.joblib, scaler.joblib,
              autoencoder.weights.h5, structural_bilstm.weights.h5,
              meta.json, sample_cases.json — real model inference.
  DEMO MODE:  any of those files missing — keyword heuristic + honest labelling.
"""
import sys, io, os, pathlib, json, time, random, importlib.util
import numpy as np
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HERE   = pathlib.Path(__file__).parent
MODELS = HERE / "models" / "ember"

# ─────────────────────────────────────────────────────────────────────────────
# Live model loader
# ─────────────────────────────────────────────────────────────────────────────
_live_state = {}   # populated once on first request if files present


def _load_live_models():
    """Try to load real model files.  Returns True on success."""
    required = ["rf_model.joblib", "scaler.joblib", "meta.json",
                "autoencoder.weights.h5", "structural_bilstm.weights.h5"]
    if not all((MODELS / f).exists() for f in required):
        missing = [f for f in required if not (MODELS / f).exists()]
        print("[CARI] DEMO MODE — missing model files:", missing)
        return False

    try:
        import joblib
        _live_state["rf"]     = joblib.load(MODELS / "rf_model.joblib")
        _live_state["scaler"] = joblib.load(MODELS / "scaler.joblib")

        with open(MODELS / "meta.json") as fh:
            meta = json.load(fh)
        _live_state["meta"] = meta

        # Load deep models only if TensorFlow available
        try:
            import tensorflow as tf
            spec = importlib.util.spec_from_file_location("model_defs", MODELS / "model_defs.py")
            md   = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(md)

            input_dim     = meta["input_dim"]
            encoding_dim  = meta["autoencoder_encoding_dim"]
            blocks        = [(n, s, e) for n, s, e in meta["feature_blocks"]]
            embed_dim     = meta["block_embed_dim"]
            lstm_units    = meta["lstm_units"]

            ae = md.build_autoencoder(input_dim, encoding_dim)
            ae.load_weights(str(MODELS / "autoencoder.weights.h5"))
            _live_state["ae"] = ae

            lstm = md.build_block_lstm_model(input_dim, blocks, embed_dim, lstm_units)
            lstm.load_weights(str(MODELS / "structural_bilstm.weights.h5"))
            _live_state["lstm"] = lstm

            print("[CARI] LIVE MODE — RF + Autoencoder + Bi-LSTM loaded OK")
        except ImportError:
            # TF not installed — RF-only live mode
            _live_state["ae"]   = None
            _live_state["lstm"] = None
            print("[CARI] SEMI-LIVE MODE — RF loaded; TensorFlow not installed (AE + LSTM unavailable)")

        # Load sample cases if present
        sc_path = MODELS / "sample_cases.json"
        if sc_path.exists():
            with open(sc_path) as fh:
                _live_state["sample_cases"] = json.load(fh)

        _live_state["loaded"] = True
        return True

    except Exception as exc:
        print(f"[CARI] Model load failed: {exc} — falling back to DEMO MODE")
        _live_state.clear()
        return False


# Try loading at startup
_live_state["loaded"] = _load_live_models()

# ─────────────────────────────────────────────────────────────────────────────
# Live inference
# ─────────────────────────────────────────────────────────────────────────────
def _normalize_ae_scores(raw_errors: np.ndarray, meta: dict) -> np.ndarray:
    """Normalize raw AE reconstruction errors to [0,1] probability proxy."""
    # Use the threshold from training as the reference point
    threshold = meta.get("ae_threshold_normalized", 0.95)
    # Simple min-max: scores above threshold → higher probability
    clipped = np.clip(raw_errors, 0, None)
    normed  = clipped / (clipped.max() + 1e-9)
    return normed


def _live_predict(features_raw: list, meta: dict):
    """Run actual inference on a 2381-float feature vector."""
    import numpy as np

    X_raw = np.array(features_raw, dtype=np.float32).reshape(1, -1)
    X_scaled = _live_state["scaler"].transform(X_raw).astype(np.float32)

    fw = meta["fusion_weights"]
    t0 = time.perf_counter()

    # Engine A: Random Forest
    rf_prob = float(_live_state["rf"].predict_proba(X_scaled)[0, 1])

    # Engine B: Autoencoder (if TF loaded)
    ae   = _live_state.get("ae")
    lstm = _live_state.get("lstm")

    if ae is not None:
        recon      = ae.predict(X_scaled, verbose=0)
        recon_err  = float(np.mean(np.square(X_scaled - recon)))
        ae_threshold_raw = meta.get("ae_threshold_raw",
                                     recon_err * 1.1)  # fallback
        ae_prob = float(np.clip(recon_err / (ae_threshold_raw * 2 + 1e-9), 0, 1))
    else:
        ae_prob = None

    # Engine C: Structural Bi-LSTM (if TF loaded)
    if lstm is not None:
        lstm_prob = float(lstm.predict(X_scaled, verbose=0)[0, 0])
    else:
        lstm_prob = None

    latency_ms = (time.perf_counter() - t0) * 1000

    # Fusion
    if ae_prob is not None and lstm_prob is not None:
        fused = fw["rf"] * rf_prob + fw["ae"] * ae_prob + fw["lstm"] * lstm_prob
        mode  = "LIVE"
    elif ae_prob is None and lstm_prob is None:
        fused = rf_prob          # RF-only live
        mode  = "RF-LIVE"
    else:
        fused = rf_prob          # partial
        mode  = "PARTIAL-LIVE"

    fused = float(np.clip(fused, 0.0, 1.0))
    label = "MALICIOUS" if fused >= 0.5 else "BENIGN"

    mid_t  = meta.get("mid_confidence_threshold", 0.50)
    high_t = meta.get("high_confidence_threshold", 0.85)
    if fused >= high_t:
        action = "immediate_containment"
    elif fused >= mid_t:
        action = "honeypot_redirect"
    else:
        action = "allow"

    # Top RF features (SHAP-style: importance * direction)
    importances = _live_state["rf"].feature_importances_
    feat_names  = meta.get("feature_columns")
    direction   = 1 if fused >= 0.5 else -1
    if feat_names:
        top_idx = np.argsort(importances)[::-1][:8]
        top_feats = [
            {"feature": feat_names[i],
             "shap_value": round(direction * float(importances[i]), 6)}
            for i in top_idx
        ]
    else:
        top_feats = []

    return {
        "demo_mode":      False,
        "inference_mode": mode,
        "label":          label,
        "fused_score":    round(fused, 4),
        "confidence_pct": round(abs(fused - 0.5) * 200, 1),
        "engine_scores": {
            "Random Forest":       round(rf_prob, 4),
            "Autoencoder":         round(ae_prob, 4)   if ae_prob   is not None else None,
            "Structural Bi-LSTM":  round(lstm_prob, 4) if lstm_prob is not None else None,
            "CARI Fused":          round(fused, 4),
        },
        "tiered_action":    action,
        "latency_ms":       round(latency_ms, 1),
        "mc_uncertainty":   None,   # MC dropout needs multiple forward passes; omit in sync path
        "high_uncertainty": False,
        "top_features":     top_feats,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Demo fallback (keyword heuristic — used only when models not loaded)
# ─────────────────────────────────────────────────────────────────────────────
MALICIOUS_KW = ["crypt","ransom","lock","wanna","mal","trojan","virus",
                 "payload","encrypt","zeus","emotet","ryuk","darkside",
                 "conti","revil","sodinokibi","locky","petya","notpetya"]
BENIGN_KW    = ["calc","notepad","chrome","firefox","update","setup","install",
                 "uninstall","svchost","explorer","winword","excel","outlook"]
TOP_FEATS_DEMO = [
    ("F2360",0.013451),("F2361",0.011711),("F638",0.011260),
    ("F509",0.008989),("F511",0.008424),("F505",0.008167),
    ("F507",0.007822),("F500",0.006944),
]

def _demo_predict(filename: str):
    fl = filename.lower()
    is_mal = any(kw in fl for kw in MALICIOUS_KW)
    is_ben = any(kw in fl for kw in BENIGN_KW) and not is_mal
    rng = random.Random(hash(filename) & 0xFFFF)
    fused = rng.uniform(0.78, 0.99) if is_mal else (
            rng.uniform(0.01, 0.22) if is_ben else
            rng.uniform(0.25, 0.85))
    def n(): return rng.uniform(-0.08, 0.08)
    rf   = max(0.01, min(0.99, fused + n()))
    ae   = max(0.01, min(0.99, fused * 0.7 + rng.uniform(0.05, 0.25)))
    lstm = max(0.01, min(0.99, fused + n()))
    unc  = rng.uniform(0.02, 0.18)
    label  = "MALICIOUS" if fused >= 0.5 else "BENIGN"
    action = "immediate_containment" if fused >= 0.85 else (
             "honeypot_redirect" if fused >= 0.50 else "allow")
    d = 1 if fused > 0.5 else -1
    feats = sorted(
        [{"feature": f, "shap_value": round(d * imp * rng.uniform(0.5, 2.0), 6)}
         for f, imp in TOP_FEATS_DEMO],
        key=lambda x: abs(x["shap_value"]), reverse=True
    )
    return {
        "demo_mode": True, "inference_mode": "DEMO",
        "filename": filename, "label": label,
        "fused_score": round(fused, 4),
        "confidence_pct": round(abs(fused - 0.5) * 200, 1),
        "engine_scores": {
            "Random Forest": round(rf, 4), "Autoencoder": round(ae, 4),
            "Structural Bi-LSTM": round(lstm, 4), "CARI Fused": round(fused, 4),
        },
        "tiered_action": action,
        "mc_uncertainty": round(unc, 4), "high_uncertainty": unc > 0.12,
        "top_features": feats,
    }


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI app
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="CARI EMBER Dashboard")


@app.get("/", response_class=HTMLResponse)
async def index():
    return (HERE / "dashboard.html").read_text(encoding="utf-8")


@app.get("/api/status")
async def status():
    live = _live_state.get("loaded", False)
    has_tf = False
    try:
        import tensorflow  # noqa
        has_tf = True
    except ImportError:
        pass
    model_files = {}
    for fname in ["rf_model.joblib", "scaler.joblib", "meta.json",
                  "autoencoder.weights.h5", "structural_bilstm.weights.h5",
                  "sample_cases.json"]:
        model_files[fname] = (MODELS / fname).exists()
    return JSONResponse({
        "live_inference": live,
        "tensorflow_installed": has_tf,
        "model_files": model_files,
        "models_dir": str(MODELS),
    })


@app.get("/api/samples")
async def get_samples():
    """Return real labeled sample feature vectors (if available)."""
    sc = _live_state.get("sample_cases")
    if sc:
        return JSONResponse({"available": True, "count": len(sc), "samples": sc})
    return JSONResponse({"available": False, "samples": []})


@app.post("/predict")
async def predict(request: Request):
    body = await request.json()
    filename = body.get("filename", "unknown.exe")
    features = body.get("features")   # list of 2381 floats for live inference

    if _live_state.get("loaded") and features is not None:
        try:
            result = _live_predict(features, _live_state["meta"])
            result["filename"] = filename
            return JSONResponse(result)
        except Exception as exc:
            print(f"[CARI] Live inference failed: {exc} — falling back to DEMO")

    # Fallback to demo mode
    return JSONResponse(_demo_predict(filename))


if __name__ == "__main__":
    live = _live_state.get("loaded", False)
    mode = "LIVE MODEL INFERENCE" if live else "DEMO MODE (models not yet downloaded)"
    print("\n" + "="*60)
    print("  CARI EMBER Ransomware Detection Dashboard")
    print(f"  Mode: {mode}")
    print("  Open: http://localhost:8000")
    print("="*60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
