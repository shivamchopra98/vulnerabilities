import os
import csv
from glob import glob
import sys

# Increase CSV field size limit
max_int = sys.maxsize
while True:
    try:
        csv.field_size_limit(max_int)
        break
    except OverflowError:
        max_int = int(max_int / 10)

# Base folder containing date-named subfolders
BASE_DIR = r"C:\Users\ShivamChopra\Projects\vulnerabilities\data"

# Step 1: Find the latest date folder
date_folders = [f for f in os.listdir(BASE_DIR)
                if os.path.isdir(os.path.join(BASE_DIR, f))]
date_folders = [f for f in date_folders if len(f) == 10 and f[4] == '-' and f[7] == '-']

if not date_folders:
    raise RuntimeError("No date folders found in the path.")

latest_folder = max(date_folders)  # latest YYYY-MM-DD folder
latest_folder_path = os.path.join(BASE_DIR, latest_folder)
print(f"Latest folder detected: {latest_folder_path}")

# Step 2: Find all CSV files in that folder
csv_files = glob(os.path.join(latest_folder_path, "*.csv"))
if not csv_files:
    raise RuntimeError("No CSV files found in the latest folder.")

print(f"Found {len(csv_files)} CSV files. Combining them...")

# Step 3: Combine all CSVs into one
OUTPUT_FILE = os.path.join(latest_folder_path, "combined_csv.csv")
seen_cves = set()  # optional: remove duplicates

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as outfile:
    writer = None

    for file in csv_files:
        with open(file, "r", encoding="utf-8") as infile:
            reader = csv.reader(infile)
            headers = next(reader)

            if writer is None:
                writer = csv.writer(outfile)
                writer.writerow(headers)

            for row in reader:
                cve = row[0]
                if cve not in seen_cves:
                    writer.writerow(row)
                    seen_cves.add(cve)

print(f"✅ All CSVs combined into: {OUTPUT_FILE}")
