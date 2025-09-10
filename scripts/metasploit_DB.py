import os
import requests
import json
import pandas as pd
import re
from datetime import datetime
import shutil

# ------------------------
# Paths
# ------------------------
TODAY = datetime.now().strftime("%Y-%m-%d")

BASE_DIR = os.path.dirname(os.path.dirname(__file__))   # project root
META_BASE = os.path.join(BASE_DIR, "metasploit_database")
META_DIR = os.path.join(META_BASE, TODAY)

os.makedirs(META_DIR, exist_ok=True)

RAW_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
JSON_FILE = os.path.join(META_DIR, "modules_metadata_base.json")
CSV_FILE = os.path.join(META_DIR, "modules_metadata_base.csv")

# ------------------------
# Helpers
# ------------------------
def cleanup_old_folders(base_dir, keep_today):
    """Delete all date folders except today's."""
    for folder in os.listdir(base_dir):
        fpath = os.path.join(base_dir, folder)
        if os.path.isdir(fpath) and folder != keep_today:
            print(f"🗑️ Removing old folder → {fpath}")
            shutil.rmtree(fpath)

def download_file(url, save_path):
    print(f"⬇️ Downloading {url}")
    resp = requests.get(url)
    resp.raise_for_status()
    with open(save_path, "wb") as f:
        f.write(resp.content)
    print(f"✅ Saved → {save_path}")

def clean_text(value: str) -> str:
    """Remove newlines, tabs, and excessive spaces for clean one-line CSV."""
    if not isinstance(value, str):
        return value
    return re.sub(r"\s+", " ", value).strip()

def clean_value(value):
    """Convert lists/dicts into clean strings for CSV and clean text values."""
    if isinstance(value, list):
        flat = []
        for v in value:
            if isinstance(v, dict):
                flat.append(";".join(f"{k}:{clean_text(str(v[k]))}" for k in v))
            else:
                flat.append(clean_text(str(v)))
        return " | ".join(flat)
    if isinstance(value, dict):
        return ";".join(f"{k}:{clean_text(str(v))}" for k, v in value.items())
    return clean_text(value)

def flatten_json(file_path, csv_path):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        df = pd.json_normalize(data, sep="_")
    elif isinstance(data, dict):
        df = pd.json_normalize(list(data.values()), sep="_")
    else:
        print("⚠️ Unsupported JSON format")
        return

    # Apply cleaning to all columns
    for col in df.columns:
        df[col] = df[col].apply(clean_value)

    # Save to CSV with proper quoting
    df.to_csv(csv_path, index=False, encoding="utf-8", quoting=1)  # quoting=1 → QUOTE_ALL
    print(f"📂 Exported {len(df)} rows and {len(df.columns)} columns → {csv_path}")

# ------------------------
# Main
# ------------------------
def main():
    # Cleanup old folders first
    cleanup_old_folders(META_BASE, TODAY)

    # Download + convert
    download_file(RAW_URL, JSON_FILE)
    flatten_json(JSON_FILE, CSV_FILE)

    # Cleanup JSON file after CSV conversion
    if os.path.exists(JSON_FILE):
        os.remove(JSON_FILE)
        print(f"🧹 Removed temporary file → {JSON_FILE}")

    print(f"🎉 Metasploit DB updated under {META_DIR}")

if __name__ == "__main__":
    main()
