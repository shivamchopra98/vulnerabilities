import requests
import json
import csv
import os

# URL of the raw JSON file
url = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"

# Base directory
base_dir = r"C:\Users\ShivamChopra\Projects\vulnerabilities"
folder_name = "joshhighetransomwatch_database"
save_dir = os.path.join(base_dir, folder_name)

# Ensure the directory exists
os.makedirs(save_dir, exist_ok=True)

# CSV filename and path
csv_filename = "joshhighetransomwatch_DB.csv"
csv_path = os.path.join(save_dir, csv_filename)

# Step 1: Download the JSON
response = requests.get(url)
response.raise_for_status()  # Raise error if download fails
data = response.json()

# Step 2: Convert JSON to CSV
if isinstance(data, dict):
    data = [data]

# Extract headers dynamically
headers = sorted({key for entry in data for key in entry.keys()})

# Step 3: Save CSV
with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=headers)
    writer.writeheader()
    writer.writerows(data)

print(f"CSV saved successfully at: {csv_path}")
