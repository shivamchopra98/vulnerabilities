import os
import requests
import pandas as pd
from pandas import json_normalize

# URL of the raw JSON file
url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"

# Save directory
save_dir = r"C:\Users\ShivamChopra\Projects\vulnerabilities\MISP_database"
os.makedirs(save_dir, exist_ok=True)
csv_path = os.path.join(save_dir, "misp_DB.csv")

# Step 1: Download JSON
response = requests.get(url)
response.raise_for_status()
data = response.json()

# Step 2: Extract threat actors list
actors = data.get("values", data)

# Step 3: Flatten with json_normalize
df = json_normalize(actors)

# Step 4: Convert nested lists/dicts into strings
def flatten_value(x):
    if isinstance(x, list):
        # If list of dicts → join dicts as JSON-like strings
        if all(isinstance(i, dict) for i in x):
            return ";".join([str(i) for i in x])
        # If list of strings/numbers → join cleanly
        return ";".join(map(str, x))
    elif isinstance(x, dict):
        # Flatten dict to key=value format
        return ";".join([f"{k}={v}" for k, v in x.items()])
    return x

df = df.applymap(flatten_value)

# Step 5: Save as CSV
df.to_csv(csv_path, index=False, encoding="utf-8")

print(f"Flattened CSV saved at: {csv_path}")
