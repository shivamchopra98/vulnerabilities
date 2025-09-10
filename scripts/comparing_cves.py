import os
import pandas as pd
from datetime import datetime

# -----------------------------
# Base paths
# -----------------------------
BASE_PARTITIONED_DIR = r"C:\Users\ShivamChopra\Projects\vulnerabilities\partitioned_cves"
YESTERDAY_DIR = r"C:\Users\ShivamChopra\Projects\vulnerabilities\base_database"  # static base DB
LOG_FILE = r"C:\Users\ShivamChopra\Projects\vulnerabilities\update_log.txt"


# -----------------------------
# Helpers
# -----------------------------
def log_message(message):
    """Append a message to the log file with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {message}\n")
    print(message)


def clean_columns(df):
    """Normalize column names: lowercase, strip spaces, remove BOM."""
    df.columns = [col.strip().lower().replace("\ufeff", "") for col in df.columns]
    return df


def find_id_column(df):
    """Find the CVE ID column in the dataframe (case insensitive)."""
    possible_cols = {"id", "cve_id"}
    for col in df.columns:
        if col.lower() in possible_cols:
            return col
    return None


def get_latest_today_dir():
    """Find the latest dated folder inside partitioned_cves/ (by folder name)."""
    subfolders = [
        os.path.join(BASE_PARTITIONED_DIR, d)
        for d in os.listdir(BASE_PARTITIONED_DIR)
        if os.path.isdir(os.path.join(BASE_PARTITIONED_DIR, d))
    ]
    if not subfolders:
        raise FileNotFoundError("No partitioned_cves folders found!")

    # Sort lexicographically by folder name (YYYY-MM-DD format ensures correct order)
    latest = max(subfolders, key=lambda x: os.path.basename(x))
    log_message(f"📂 Using latest data folder: {latest}")
    return latest


# -----------------------------
# Update Logic
# -----------------------------
def update_partition(yesterday_file, today_file):
    if not os.path.exists(today_file):
        log_message(f"⚠️ Skipping {today_file}, no data today.")
        return
    if not os.path.exists(yesterday_file):
        log_message(f"📂 New file → copying {today_file} to {yesterday_file}")
        os.makedirs(os.path.dirname(yesterday_file), exist_ok=True)
        pd.read_csv(today_file).to_csv(yesterday_file, index=False, encoding="utf-8-sig")
        return

    # Load both
    df_y = pd.read_csv(yesterday_file, encoding="utf-8-sig")
    df_t = pd.read_csv(today_file, encoding="utf-8-sig")

    df_y = clean_columns(df_y)
    df_t = clean_columns(df_t)

    id_col_y = find_id_column(df_y)
    id_col_t = find_id_column(df_t)

    if not id_col_y or not id_col_t:
        log_message(f"❌ Skipping {today_file}: No CVE ID column found.")
        return

    df_y = df_y.rename(columns={id_col_y: "id"})
    df_t = df_t.rename(columns={id_col_t: "id"})

    if "lastmodified" not in df_y.columns or "lastmodified" not in df_t.columns:
        log_message(f"❌ Skipping {today_file}: No 'lastModified' column found.")
        return

    # Merge on id
    merged = pd.merge(df_y, df_t, on="id", how="outer", suffixes=("_y", "_t"))

    updated_rows, updates, additions = [], [], []

    for _, row in merged.iterrows():
        if pd.notna(row.get("lastmodified_t")):  # exists in today's
            if pd.isna(row.get("lastmodified_y")):  # new CVE
                new_row = row.filter(like="_t").rename(lambda x: x[:-2])
                updated_rows.append(new_row)
                additions.append(row["id"])
            else:  # compare lastModified
                if row["lastmodified_t"] > row["lastmodified_y"]:
                    new_row = row.filter(like="_t").rename(lambda x: x[:-2])
                    updated_rows.append(new_row)
                    updates.append(row["id"])
                else:
                    new_row = row.filter(like="_y").rename(lambda x: x[:-2])
                    updated_rows.append(new_row)
        else:  # only in yesterday
            new_row = row.filter(like="_y").rename(lambda x: x[:-2])
            updated_rows.append(new_row)

    updated_df = pd.DataFrame(updated_rows)

    # Ensure "id" column always exists
    if "id" not in updated_df.columns:
        updated_df.insert(0, "id", merged["id"])

    updated_df.to_csv(yesterday_file, index=False, encoding="utf-8-sig")

    if additions or updates:
        log_message(f"✅ {yesterday_file} updated: {len(additions)} new, {len(updates)} modified")
        if additions:
            log_message(f"   ➕ New CVEs: {', '.join(additions)}")
        if updates:
            log_message(f"   🔄 Updated CVEs: {', '.join(updates)}")
    else:
        log_message(f"ℹ️ {yesterday_file} had no changes.")


def update_all():
    log_message("🚀 Starting daily CVE comparison job...")

    today_dir = get_latest_today_dir()  # detect latest dated folder

    for root, _, files in os.walk(today_dir):
        for fname in files:
            if fname.endswith(".csv"):
                rel_path = os.path.relpath(os.path.join(root, fname), today_dir)
                today_file = os.path.join(today_dir, rel_path)
                yesterday_file = os.path.join(YESTERDAY_DIR, rel_path)

                update_partition(yesterday_file, today_file)

    log_message("🎉 All partitions compared and updated\n")


# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    update_all()
