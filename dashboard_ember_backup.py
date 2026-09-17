import os, pathlib, random
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

HERE = pathlib.Path(__file__).parent

MALICIOUS_KEYWORDS = [
    "crypt","ransom","lock","wanna","mal","trojan","virus",
    "payload","encrypt","zeus","emotet","ryuk","darkside",
    "conti","revil","sodinokibi","locky","petya","notpetya",
]
BENIGN_KEYWORDS = [
    "calc","notepad","chrome","firefox","update","setup","install",
    "uninstall","svchost","explorer","winword","excel","outlook",
]
TOP_FEATS = [
    ("F2360",0.013451),("F2361",0.011711),("F638",0.011260),
    ("F509",0.008989),("F511",0.008424),("F505",0.008167),
    ("F507",0.007822),("F500",0.006944),("F502",0.006766),
    ("F659",0.006765),("F504",0.006342),("F501",0.006030),
]

def demo_predict(filename: str):
    fname_lower = filename.lower()
    is_mal  = any(kw in fname_lower for kw in MALICIOUS_KEYWORDS)
    is_ben  = any(kw in fname_lower for kw in BENIGN_KEYWORDS) and not is_mal
    rng = random.Random(hash(filename) & 0xFFFF)
    if is_mal:
        fused = rng.uniform(0.78, 0.99)
    elif is_ben:
        fused = rng.uniform(0.01, 0.22)
    else:
        fused = rng.uniform(0.25, 0.85)
    def n(): return rng.uniform(-0.08, 0.08)
    rf    = max(0.01, min(0.99, fused + n()))
    ae    = max(0.01, min(0.99, fused * 0.7 + rng.uniform(0.05, 0.25)))
    lstm  = max(0.01, min(0.99, fused + n()))
    unc   = rng.uniform(0.02, 0.18)
    label = "MALICIOUS" if fused >= 0.5 else "BENIGN"
    action= "immediate_containment" if fused>=0.85 else ("honeypot_redirect" if fused>=0.50 else "allow")
    feats = []
    for feat, imp in TOP_FEATS[:8]:
        d = 1 if fused > 0.5 else -1
        feats.append({"feature": feat, "shap_value": round(d * imp * rng.uniform(0.5, 2.0), 6)})
    feats.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
    return {
        "demo_mode": True, "filename": filename, "label": label,
        "fused_score": round(fused,4),
        "confidence_pct": round(abs(fused-0.5)*200,1),
        "engine_scores": {
            "Random Forest": round(rf,4), "Autoencoder": round(ae,4),
            "Structural Bi-LSTM": round(lstm,4), "CARI Fused": round(fused,4),
        },
        "tiered_action": action,
        "mc_uncertainty": round(unc,4), "high_uncertainty": unc>0.12,
        "top_features": feats,
    }

app = FastAPI(title="CARI Dashboard")

@app.get("/", response_class=HTMLResponse)
async def index():
    html_file = HERE / "dashboard.html"
    return html_file.read_text(encoding="utf-8")

@app.post("/predict")
async def predict(request: Request):
    body = await request.json()
    return JSONResponse(demo_predict(body.get("filename","unknown.exe")))

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  CARI Ransomware Detection Dashboard")
    print("  DEMO MODE — real notebook metrics, simulated prediction")
    print("  Open: http://localhost:8000")
    print("="*60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
