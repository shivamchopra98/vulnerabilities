import csv
import requests
import time
import os
import sys

# Increase CSV field size limit to handle very large fields
max_int = sys.maxsize
while True:
    try:
        csv.field_size_limit(max_int)
        break
    except OverflowError:
        max_int = int(max_int / 10)

# Paths
INPUT_CSV = r"C:\Users\ShivamChopra\Projects\vulnerabilities\data\combined.csv"
OUTPUT_DIR = r"C:\Users\ShivamChopra\Projects\vulnerabilities\epss_database"
os.makedirs(OUTPUT_DIR, exist_ok=True)
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "epss_DB.csv")

# Config
BATCH_SIZE = 100           # number of CVEs per API call
SLEEP_TIME = 0.06          # ~1000 requests per minute
API_URL = "https://api.first.org/data/v1/epss"

# Step 1: Read CVEs from the first column (id)
cve_list = []
with open(INPUT_CSV, "r", encoding="utf-8") as f:
    reader = csv.reader(f)
    header = next(reader)  # skip header
    for row in reader:
        if len(row) >= 1:
            cve_id = row[0].strip()
            if cve_id:
                cve_list.append(cve_id)

print(f"Total CVEs to process: {len(cve_list)}")

# Step 2: Check existing output to support resuming
if os.path.exists(OUTPUT_CSV):
    processed_cves = set()
    with open(OUTPUT_CSV, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)  # skip header
        for row in reader:
            if len(row) >= 1:
                processed_cves.add(row[0].strip())
    print(f"Resuming... {len(processed_cves)} CVEs already processed.")
else:
    processed_cves = set()
    # create CSV with header
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["cve", "epss", "percentile", "date"])

# Step 3: Process CVEs in batches
for i in range(0, len(cve_list), BATCH_SIZE):
    batch = [cve for cve in cve_list[i:i+BATCH_SIZE] if cve not in processed_cves]
    if not batch:
        continue  # skip if all CVEs already processed

    batch_str = ",".join(batch)
    url = f"{API_URL}?cve={batch_str}&pretty=true"

    try:
        resp = requests.get(url)
        if resp.status_code == 429:
            print("Rate limit exceeded. Sleeping for 120 seconds...")
            time.sleep(120)
            continue
        elif resp.status_code != 200:
            print(f"Error {resp.status_code} for batch {i//BATCH_SIZE + 1}")
            time.sleep(SLEEP_TIME)
            continue

        data = resp.json().get("data", [])
        with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for item in data:
                writer.writerow([item["cve"], item["epss"], item["percentile"], item["date"]])
                processed_cves.add(item["cve"])

        print(f"Batch {i//BATCH_SIZE + 1}: Processed {len(batch)} CVEs. Total so far: {len(processed_cves)}")
        time.sleep(SLEEP_TIME)

    except Exception as e:
        print(f"Exception during batch {i//BATCH_SIZE + 1}: {e}")
        time.sleep(SLEEP_TIME)

print("✅ All CVEs processed. Data saved to:", OUTPUT_CSV)
