# CARI — AI-Based Ransomware Detection 

**Cloud-Adaptive Ransomware Intelligence Framework**

---

## Overview



### Why Behavioral Detection?

Static PE analysis (EMBER) cannot detect encrypted, packed, or obfuscated ransomware.
Behavioral ATA-trace analysis detects ransomware by its distinctive **write patterns**:
- High-throughput sequential block overwrites (encryption)
- Wide LBA range access (targeting many files)
- Low sequential-access ratio (random seeks during encryption)
- High burst activity and size entropy

### Detection Pipeline

```
EMBER
     ↓
Feature Extraction (per run)
     ↓
RF + XGBoost + Autoencoder
     ↓
AUC-Weighted CARI Fusion
     ↓
Tiered Response: Allow / Honeypot / Contain
```

---

## Project Structure

```
AI-Based-Ransomware-Detection/
├── dashboard.py                  ← FastAPI dashboard server (RanSAP)
├── dashboard.html                ← Dashboard UI (RanSAP)
├── ransap_pipeline.py            ← ML pipeline: feature extraction + training
├── DOWNLOAD_INSTRUCTIONS.md      ← Exactly which files to download
├── README.md                     ← This file
│
├── data/ransap/                  ← Place RanSAP CSV files here
│   ├── AESCrypt/
│   ├── Cerber-w10dirs/
│   ├── Darkside-w10dirs/
│   ├── Ryuk-w10dirs/
│   ├── Sodinokibi-w10dirs/
│   ├── TeslaCrypt-w10dirs/
│   ├── WannaCry-w10dirs/
│   ├── Excel/
│   ├── Firefox/
│   └── Zip/
│
├── models/ransap/                ← Trained model artifacts
│   ├── rf_model.joblib
│   ├── xgb_model.joblib
│   ├── autoencoder.joblib
│   ├── scaler.joblib
│   └── results.json              ← All metrics (read by dashboard)
│
├── ransap_file_list.csv          ← RanSAP complete file listing
├── ransap_page1.csv, page2.csv   ← Additional file listings
│
└── EMBER Backup (original project)
    ├── dashboard_ember_backup.py
    ├── dashboard_ember_backup.html
    └── notebooks/
        └── CARI_Ransomware_Detectiongfytfytfyftf.ipynb
```

---

## Quick Start

### Step 1 — Download RanSAP Files
See [DOWNLOAD_INSTRUCTIONS.md](DOWNLOAD_INSTRUCTIONS.md).
Download ~14 CSV files (~460 MB) and place in `data/ransap/`.

### Step 2 — Run the ML Pipeline
```powershell
cd "C:\Users\tombo\OneDrive\Attachments\Desktop\AI-Based-Ransomware-Detection"
.venv\Scripts\python.exe ransap_pipeline.py
```

This trains all models and saves `models/ransap/results.json`.

### Step 3 — Start the Dashboard
```powershell
.venv\Scripts\python.exe dashboard.py
```

Open: **http://localhost:8000**

---

## Models

| Model | Role |
|---|---|
| Random Forest | Main classifier + SHAP explainability |
| XGBoost | Gradient-boosted comparison model |
| Autoencoder | Anomaly detection (trained on benign only) |
| CARI Fused | AUC-weighted ensemble of all three |

---

## Extracted Features

All features are extracted per execution run from `ata_write.csv`:

| Feature | Description |
|---|---|
| `total_ops` | Total write operations |
| `total_bytes` | Total bytes written |
| `ops_per_sec` | Write throughput (ops/second) |
| `mean_size` / `std_size` | Transfer size distribution |
| `mean_lba` / `std_lba` / `lba_range` | LBA access spread |
| `sequential_ratio` | Fraction of sequential accesses |
| `unique_lba_ratio` | Fraction of unique LBAs accessed |
| `burst_count` | Number of burst activity events |
| `size_entropy` | Shannon entropy of write sizes |
| `bytes_per_op` | Average bytes per write operation |
| `duration` | Total execution window (seconds) |

---

## Dataset

**RanSAP** — Storage-Access Pattern dataset for ransomware detection.

- Platform: Windows Server 2008 R2, 250GB SSD
- Capture method: ATA command tracing
- Ransomware families: AESCrypt, Cerber, DarkSide, Ryuk, Sodinokibi (REvil), TeslaCrypt, WannaCry
- Benign software: Excel, Firefox, 7-Zip

> **Safety:** Only CSV behavioral logs are used. No executables are downloaded or run.

---

## EMBER Backup

The original EMBER-based static PE detection implementation is preserved:
- `dashboard_ember_backup.py` / `dashboard_ember_backup.html`
- `notebooks/CARI_Ransomware_Detectiongfytfytfyftf.ipynb`

To run the EMBER dashboard instead:
```powershell
.venv\Scripts\python.exe dashboard_ember_backup.py
```
