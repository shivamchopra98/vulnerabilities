import os
import requests
import lzma
import json
import pandas as pd
import re
import shutil
from datetime import datetime

# ------------------------
# Paths with today's date
# ------------------------
TODAY = datetime.now().strftime("%Y-%m-%d")

BASE_DIR = os.path.dirname(os.path.dirname(__file__))   # project root
DATA_PARENT = os.path.join(BASE_DIR, "data")
PARTITION_PARENT = os.path.join(BASE_DIR, "partitioned_cves")

DATA_DIR = os.path.join(DATA_PARENT, TODAY)
PARTITION_DIR = os.path.join(PARTITION_PARENT, TODAY)

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(PARTITION_DIR, exist_ok=True)

# ------------------------
# GitHub Repo Info
# ------------------------
OWNER = "fkie-cad"
REPO = "nvd-json-data-feeds"

# ------------------------
# Target CVE Files
# ------------------------
TARGET_FILES = {f"CVE-{year}.json.xz" for year in range(1999, 2026)}

# ------------------------
# Helpers (cleaning)
# ------------------------
def clean_text(value: str) -> str:
    if not isinstance(value, str):
        return value
    return re.sub(r"\s+", " ", value).strip()

def safe_json_dumps(value):
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, str):
        return clean_text(value)
    return value

# ------------------------
# Step 0: Cleanup Old Folders
# ------------------------
def cleanup_old_folders(parent_dir, keep_today):
    """Delete all date folders except today's."""
    for d in os.listdir(parent_dir):
        folder_path = os.path.join(parent_dir, d)
        if os.path.isdir(folder_path) and re.match(r"\d{4}-\d{2}-\d{2}", d):
            if d != keep_today:
                print(f"🗑️ Removing old folder: {folder_path}")
                shutil.rmtree(folder_path)

# ------------------------
# Step 1: Fetch release assets (latest release)
# ------------------------
def get_json_xz_urls():
    api_url = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/latest"
    print(f"🔎 Fetching latest release info from {api_url}")
    resp = requests.get(api_url)
    resp.raise_for_status()
    assets = resp.json().get("assets", [])
    
    urls = []
    for asset in assets:
        name = asset["name"]
        if name in TARGET_FILES:
            urls.append((name, asset["browser_download_url"]))
    print(f"✅ Found {len(urls)} yearly CVE files")
    return urls

# ------------------------
# Step 2: Download + Extract + Convert
# ------------------------
def download_file(url, save_path):
    resp = requests.get(url, stream=True)
    resp.raise_for_status()
    with open(save_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)

def extract_xz(xz_path, json_path):
    with lzma.open(xz_path) as f:
        data = f.read()
    with open(json_path, "wb") as f:
        f.write(data)

def extract_english_description(desc_list):
    if not isinstance(desc_list, list):
        return ""
    for d in desc_list:
        if isinstance(d, dict) and d.get("lang") == "en":
            return d.get("value", "")
    return ""

def flatten_json(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vulns = data.get("vulnerabilities") or data.get("cve_items") or data.get("CVE_Items") or []
    if not vulns:
        return pd.DataFrame()

    if "cve" in vulns[0]:
        cve_records = [v.get("cve", {}) for v in vulns]
    else:
        cve_records = vulns

    df = pd.json_normalize(cve_records, sep="_")

    if "descriptions" in df.columns:
        df["descriptions"] = df["descriptions"].apply(extract_english_description)

    for col in df.columns:
        df[col] = df[col].apply(safe_json_dumps)

    return df

def json_to_csv(json_path, csv_path):
    df = flatten_json(json_path)
    if not df.empty:
        df.to_csv(csv_path, index=False, encoding="utf-8")
        print(f"✅ Exported {len(df)} CVEs → {csv_path}")

# ------------------------
# Step 3: Partition CSVs automatically
# ------------------------
def get_partition_info(cve_id):
    parts = cve_id.split("-")
    year = parts[1]
    number = int(parts[2])
    thousand_group = number // 1000
    return year, thousand_group

def partition_csv(input_file, output_dir):
    df = pd.read_csv(input_file)

    groups = {}
    for _, row in df.iterrows():
        cve_id = row["id"]
        year, thousand_group = get_partition_info(cve_id)
        key = (year, thousand_group)
        groups.setdefault(key, []).append(row)

    for (year, thousand_group), rows in groups.items():
        folder_path = os.path.join(output_dir, year, str(thousand_group))
        os.makedirs(folder_path, exist_ok=True)

        output_file = os.path.join(folder_path, f"CVE-{year}-{thousand_group}.csv")
        pd.DataFrame(rows).to_csv(output_file, index=False)
        print(f"📂 Partitioned {len(rows)} CVEs → {output_file}")

# ------------------------
# Main Flow
# ------------------------
def main():
    # Cleanup yesterday’s data before running
    cleanup_old_folders(DATA_PARENT, TODAY)
    cleanup_old_folders(PARTITION_PARENT, TODAY)

    # Fetch + Convert
    files = get_json_xz_urls()
    for name, url in files:
        xz_path = os.path.join(DATA_DIR, name)
        json_path = xz_path.replace(".json.xz", ".json")
        csv_path = xz_path.replace(".json.xz", ".csv")

        print(f"⬇️ Downloading {name}")
        download_file(url, xz_path)
        extract_xz(xz_path, json_path)
        json_to_csv(json_path, csv_path)

        os.remove(xz_path)
        os.remove(json_path)

    # Partition all CSVs automatically
    for fname in os.listdir(DATA_DIR):
        if fname.endswith(".csv"):
            file_path = os.path.join(DATA_DIR, fname)
            partition_csv(file_path, PARTITION_DIR)

    print(f"🎉 All CVE files processed & partitioned under {TODAY}")

if __name__ == "__main__":
    main()
