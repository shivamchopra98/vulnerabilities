import os
import time
import pandas as pd
from datetime import datetime
from bs4 import BeautifulSoup
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# -----------------------------
# Config
# -----------------------------
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
TODAY = datetime.now().strftime("%Y-%m-%d")

# base_database path (with space, matching your folder)
BASE_DB_DIR = os.path.join(BASE_DIR, "corelabs_database", "base _database")
os.makedirs(BASE_DB_DIR, exist_ok=True)

BASE_DB = os.path.join(BASE_DB_DIR, "baseDB.csv")
NEW_CSV = os.path.join(BASE_DB_DIR, f"new_corelabs_exploits_{TODAY}.csv")

BASE_URL = "https://www.coresecurity.com/core-labs/exploits"

# -----------------------------
# Scraper
# -----------------------------
def scrape_first_page():
    """Scrape only the first page and return rows."""
    options = uc.ChromeOptions()
    options.headless = False  # set True if you don’t want to see the browser
    driver = uc.Chrome(options=options)

    url = BASE_URL
    driver.get(url)

    try:
        WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.TAG_NAME, "table"))
        )
    except Exception:
        print("⚠️ Timeout loading first page")
        driver.quit()
        return []

    soup = BeautifulSoup(driver.page_source, "html.parser")
    driver.quit()

    table = soup.find("table")
    if not table:
        print("⚠️ No table found on first page")
        return []

    rows = []
    for tr in table.find("tbody").find_all("tr"):
        cols = [td.get_text(strip=True) for td in tr.find_all("td")]
        rows.append(cols)

    return rows

# -----------------------------
# Compare and update DB
# -----------------------------
def update_base_db(new_csv, base_db):
    new_df = pd.read_csv(new_csv)

    if os.path.exists(base_db):
        base_df = pd.read_csv(base_db)

        # Find new rows (by "Date Added" + "Title" uniqueness)
        merged = pd.merge(new_df, base_df, on=["Title", "Date Added"], how="left", indicator=True)
        new_entries = merged[merged["_merge"] == "left_only"].drop(columns=["_merge"])

        if not new_entries.empty:
            print(f"➕ Found {len(new_entries)} new entries. Appending to baseDB...")
            updated_df = pd.concat([base_df, new_entries], ignore_index=True)
            updated_df.to_csv(base_db, index=False, encoding="utf-8")
        else:
            print("ℹ️ No new entries found. BaseDB already up to date.")
    else:
        print("⚠️ Base DB not found. Creating a new one.")
        new_df.to_csv(base_db, index=False, encoding="utf-8")

    # cleanup new file
    if os.path.exists(new_csv):
        os.remove(new_csv)
        print(f"🧹 Removed temporary file {new_csv}")

# -----------------------------
# Main
# -----------------------------
def main():
    headers = [
        "Title", "Description", "Date Added", "CVE Link",
        "Exploit Platform", "Exploit Type", "Product Name"
    ]

    print("📄 Scraping first page ...")
    rows = scrape_first_page()
    if not rows:
        print("⚠️ No data scraped.")
        return

    new_df = pd.DataFrame(rows, columns=headers)
    new_df.to_csv(NEW_CSV, index=False, encoding="utf-8")
    print(f"✅ Saved {len(new_df)} exploits → {NEW_CSV}")

    update_base_db(NEW_CSV, BASE_DB)


if __name__ == "__main__":
    main()
