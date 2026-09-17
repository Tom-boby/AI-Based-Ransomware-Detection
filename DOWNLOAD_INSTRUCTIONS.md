# CARI — RanSAP Download Instructions

## Files You Need to Download

Go to the **RanSAP Kaggle dataset**:
> **https://www.kaggle.com/datasets/kiddroofy/ransap**

Navigate into: `RanSAP/dataset/extra/win2008r2-250gb-ssd/`

Download **only these specific files** (one per row):

### Ransomware Files (~430 MB total)

| Family folder | Run folder | File to download |
|---|---|---|
| `AESCrypt` | `AESCrypt-20201126_21-50-04` | `ata_write.csv` (23 MB) |
| `AESCrypt` | `AESCrypt-20201126_23-23-18` | `ata_write.csv` (24 MB) |
| `Cerber-w10dirs` | `Cerber-20210126_20-07-53` | `ata_write.csv` (46 MB) |
| `Darkside-w10dirs` | `Darkside-20210714_19-24-10` | `ata_write.csv` (42 MB) |
| `Ryuk-w10dirs` | `Ryuk-20201216_20-18-25` | `ata_write.csv` (83 MB) |
| `Sodinokibi-w10dirs` | `Sodinokibi-20210624_02-28-38` | `ata_write.csv` (59 MB) |
| `TeslaCrypt-w10dirs` | `TeslaCrypt-20210126_19-31-53` | `ata_write.csv` (59 MB) |
| `WannaCry-w10dirs` | `WannaCry-20201029_21-54-49` | `ata_write.csv` (64 MB) |

### Benign Files (~30 MB total)

| Family folder | Run folder | File to download |
|---|---|---|
| `Excel` | `Excel-20210708_21-44-34` | `ata_write.csv` (1.3 MB) |
| `Excel` | `Excel-20210708_22-01-42` | `ata_write.csv` (1.5 MB) |
| `Firefox` | `Firefox-20210714_22-08-39` | `ata_write.csv` (2.4 MB) |
| `Firefox` | `Firefox-20210714_22-00-35` | `ata_write.csv` (2.4 MB) |
| `Zip` | `Zip-20201215_19-06-34` | `ata_write.csv` (11 MB) |
| `Zip` | `Zip-20201215_19-22-50` | `ata_write.csv` (16 MB) |

---

## Where to Place the Files

**Project root:** `AI-Based-Ransomware-Detection/`

Place each downloaded file at exactly this path (create the folders if missing):

```
data/ransap/
  AESCrypt/
    AESCrypt-20201126_21-50-04/ata_write.csv
    AESCrypt-20201126_23-23-18/ata_write.csv
  Cerber-w10dirs/
    Cerber-20210126_20-07-53/ata_write.csv
  Darkside-w10dirs/
    Darkside-20210714_19-24-10/ata_write.csv
  Ryuk-w10dirs/
    Ryuk-20201216_20-18-25/ata_write.csv
  Sodinokibi-w10dirs/
    Sodinokibi-20210624_02-28-38/ata_write.csv
  TeslaCrypt-w10dirs/
    TeslaCrypt-20210126_19-31-53/ata_write.csv
  WannaCry-w10dirs/
    WannaCry-20201029_21-54-49/ata_write.csv
  Excel/
    Excel-20210708_21-44-34/ata_write.csv
    Excel-20210708_22-01-42/ata_write.csv
  Firefox/
    Firefox-20210714_22-08-39/ata_write.csv
    Firefox-20210714_22-00-35/ata_write.csv
  Zip/
    Zip-20201215_19-06-34/ata_write.csv
    Zip-20201215_19-22-50/ata_write.csv
```

> The `data/ransap/` directories are already created for you. Just place the CSV files inside.

---

## After Placing Files

Run the pipeline (from the project folder):

```powershell
cd "C:\Users\tombo\OneDrive\Attachments\Desktop\AI-Based-Ransomware-Detection"
.venv\Scripts\python.exe ransap_pipeline.py
```

This will:
1. Auto-detect the CSV schema from your files
2. Extract behavioral features per run
3. Train Random Forest, XGBoost, Autoencoder, CARI Fusion
4. Evaluate and save results to `models/ransap/results.json`
5. Save model files to `models/ransap/`

Then start the dashboard:

```powershell
.venv\Scripts\python.exe dashboard.py
```

Open: **http://localhost:8000**

---

## Option B: Download via Kaggle CLI (Recommended)

Run these exact commands in your terminal from your project root (`AI-Based-Ransomware-Detection`). 

### PowerShell Commands:

```powershell
# Create destination directories
New-Item -ItemType Directory -Force -Path "data/ransap/AESCrypt/AESCrypt-20201126_21-50-04"
New-Item -ItemType Directory -Force -Path "data/ransap/AESCrypt/AESCrypt-20201126_23-23-18"
New-Item -ItemType Directory -Force -Path "data/ransap/Cerber-w10dirs/Cerber-20210126_20-07-53"
New-Item -ItemType Directory -Force -Path "data/ransap/Darkside-w10dirs/Darkside-20210714_19-24-10"
New-Item -ItemType Directory -Force -Path "data/ransap/Ryuk-w10dirs/Ryuk-20201216_20-18-25"
New-Item -ItemType Directory -Force -Path "data/ransap/Sodinokibi-w10dirs/Sodinokibi-20210624_02-28-38"
New-Item -ItemType Directory -Force -Path "data/ransap/TeslaCrypt-w10dirs/TeslaCrypt-20210126_19-31-53"
New-Item -ItemType Directory -Force -Path "data/ransap/WannaCry-w10dirs/WannaCry-20201029_21-54-49"
New-Item -ItemType Directory -Force -Path "data/ransap/Excel/Excel-20210708_21-44-34"
New-Item -ItemType Directory -Force -Path "data/ransap/Excel/Excel-20210708_22-01-42"
New-Item -ItemType Directory -Force -Path "data/ransap/Firefox/Firefox-20210714_22-00-35"
New-Item -ItemType Directory -Force -Path "data/ransap/Firefox/Firefox-20210714_22-08-39"
New-Item -ItemType Directory -Force -Path "data/ransap/Zip/Zip-20201215_19-06-34"
New-Item -ItemType Directory -Force -Path "data/ransap/Zip/Zip-20201215_19-22-50"

# Download Ransomware CSVs
kaggle datasets download -d kiddroofy/ransap -f "RanSAP/dataset/extra/win2008r2-250gb-ssd/AESCrypt/AESCrypt-20201126_21-50-04/ata_write.csv" -p "data/ransap/AESCrypt/AESCrypt-20201126_21-50-04" --unzip
kaggle datasets download -d kiddroofy/ransap -f "RanSAP/dataset/extra/win2008r2-250gb-ssd/AESCrypt/AESCrypt-20201126_23-23-18/ata_write.csv" -p "data/ransap/AESCrypt/AESCrypt-20201126_23-23-18" --unzip
kaggle datasets download -d kiddroofy/ransap -f "RanSAP/dataset/extra/win2008r2-250gb-ssd/Cerber-w10dirs/Cerber-20210126_20-07-53/ata_write.csv" -p "data/ransap/Cerber-w10dirs/Cerber-20210126_20-07-53" --unzip
kaggle datasets download -d kiddroofy/ransap -f "RanSAP/dataset/extra/win2008r2-250gb-ssd/Darkside-w10dirs/Darkside-20210714_19-24-10/ata_write.csv" -p "data/ransap/Darkside-w10dirs/Darkside-20210714_19-24-10" --unzip
kaggle datasets download -d kiddroofy/ransap -f "RanSAP/dataset/extra/win2008r2-250gb-ssd/Ryuk-w10dirs/Ryuk-20201216_20-18-25/ata_write.csv" -p "data/ransap/Ryuk-w10dirs/Ryuk-20201216_20-18-25" --unzip
kaggle datasets download -d kiddroofy/ransap -f "RanSAP/dataset/extra/win2008r2-250gb-ssd/Sodinokibi-w10dirs/Sodinokibi-20210624_02-28-38/ata_write.csv" -p "data/ransap/Sodinokibi-w10dirs/Sodinokibi-20210624_02-28-38" --unzip
kaggle datasets download -d kiddroofy/ransap -f "RanSAP/dataset/extra/win2008r2-250gb-ssd/TeslaCrypt-w10dirs/TeslaCrypt-20210126_19-31-53/ata_write.csv" -p "data/ransap/TeslaCrypt-w10dirs/TeslaCrypt-20210126_19-31-53" --unzip
kaggle datasets download -d kiddroofy/ransap -f "RanSAP/dataset/extra/win2008r2-250gb-ssd/WannaCry-w10dirs/WannaCry-20201029_21-54-49/ata_write.csv" -p "data/ransap/WannaCry-w10dirs/WannaCry-20201029_21-54-49" --unzip

# Download Benign CSVs
kaggle datasets download -d kiddroofy/ransap -f "RanSAP/dataset/extra/win2008r2-250gb-ssd/Excel/Excel-20210708_21-44-34/ata_write.csv" -p "data/ransap/Excel/Excel-20210708_21-44-34" --unzip
kaggle datasets download -d kiddroofy/ransap -f "RanSAP/dataset/extra/win2008r2-250gb-ssd/Excel/Excel-20210708_22-01-42/ata_write.csv" -p "data/ransap/Excel/Excel-20210708_22-01-42" --unzip
kaggle datasets download -d kiddroofy/ransap -f "RanSAP/dataset/extra/win2008r2-250gb-ssd/Firefox/Firefox-20210714_22-00-35/ata_write.csv" -p "data/ransap/Firefox/Firefox-20210714_22-00-35" --unzip
kaggle datasets download -d kiddroofy/ransap -f "RanSAP/dataset/extra/win2008r2-250gb-ssd/Firefox/Firefox-20210714_22-08-39/ata_write.csv" -p "data/ransap/Firefox/Firefox-20210714_22-08-39" --unzip
kaggle datasets download -d kiddroofy/ransap -f "RanSAP/dataset/extra/win2008r2-250gb-ssd/Zip/Zip-20201215_19-06-34/ata_write.csv" -p "data/ransap/Zip/Zip-20201215_19-06-34" --unzip
kaggle datasets download -d kiddroofy/ransap -f "RanSAP/dataset/extra/win2008r2-250gb-ssd/Zip/Zip-20201215_19-22-50/ata_write.csv" -p "data/ransap/Zip/Zip-20201215_19-22-50" --unzip
```


## Safety Note

These are **CSV behavioral logs only** — not executable binaries.
No ransomware code is downloaded or executed. The CSV files contain
ATA storage-access traces (timestamps, LBA addresses, transfer sizes)
recorded from a controlled VM environment.
