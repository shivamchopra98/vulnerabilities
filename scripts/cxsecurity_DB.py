import re
import csv
import time
import random
import logging
import os
import json
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# ----------------------
# Logging setup
# ----------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ----------------------
# Chrome driver setup
# ----------------------
chrome_options = Options()
# chrome_options.add_argument("--headless=new")  # keep visible to avoid bot detection
chrome_options.add_argument("--disable-gpu")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")
chrome_options.add_argument("--start-maximized")

service = Service(r"C:\Users\ShivamChopra\Downloads\chromedriver-win64\chromedriver.exe")
driver = webdriver.Chrome(service=service, options=chrome_options)

# ----------------------
# CSV / folders setup
# ----------------------
output_dir = r"C:\Users\ShivamChopra\Projects\vulnerabilities\cxsecurity_database"
os.makedirs(output_dir, exist_ok=True)

output_file = os.path.join(output_dir, "cxsecurity_DB.csv")
progress_file = os.path.join(output_dir, "progress.json")

csv_headers = ["Risk", "Title", "URL", "Tags", "Access", "Author",
               "Local", "Remote", "CVE", "CWE"]

# ----------------------
# Resume from existing CSV
# ----------------------
processed_urls = set()
if os.path.exists(output_file):
    with open(output_file, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            processed_urls.add(row['URL'])
    logging.info(f"Resuming scrape. Already processed {len(processed_urls)} URLs.")

# ----------------------
# Progress Handling
# ----------------------
def load_progress():
    if os.path.exists(progress_file):
        with open(progress_file, "r") as f:
            return json.load(f)
    return {"page": 56, "row": 60}  # default start point

def save_progress(page, row):
    with open(progress_file, "w") as f:
        json.dump({"page": page, "row": row}, f)

progress = load_progress()
page_num = progress["page"]
start_row = progress["row"]

# ----------------------
# Open main page
# ----------------------
base_url = "https://cxsecurity.com/wlb/"
driver.get(f"{base_url}{page_num}/" if page_num > 1 else base_url)
time.sleep(random.uniform(3, 6))
logging.info("Starting scrape")

# ----------------------------------
# Helper: append a single row to CSV
# ----------------------------------
def append_to_csv(row):
    file_exists = os.path.exists(output_file)
    with open(output_file, "a", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

# ----------------------
# Scrape one page
# ----------------------
def scrape_page(page_num, start_from=1):
    try:
        WebDriverWait(driver, 15).until(
            EC.presence_of_all_elements_located((By.CSS_SELECTOR, "table.table-striped tbody tr"))
        )
    except Exception:
        logging.warning(f"Page {page_num} failed to load properly")
        return

    rows = driver.find_elements(By.CSS_SELECTOR, "table.table-striped tbody tr")
    logging.info(f"Found {len(rows)} rows on page {page_num}")

    for row_idx, row in enumerate(rows, start=1):
        if row_idx < start_from:  # skip already scraped rows
            continue
        try:
            tds = row.find_elements(By.TAG_NAME, "td")
            if len(tds) < 2:
                continue

            # Risk from table
            try:
                risk = tds[0].find_element(By.TAG_NAME, "span").text.strip()
            except:
                risk = ""

            # Title + URL
            title_element = tds[1].find_element(By.TAG_NAME, "a")
            title = title_element.text.strip()
            url = title_element.get_attribute("href")

            # Skip if already processed
            if url in processed_urls:
                logging.info(f"[P{page_num} R{row_idx}] Already scraped, skipping: {title}")
                continue

            # Tags & Access
            labels = tds[1].find_elements(By.CSS_SELECTOR, "span.label")
            tags = [lbl.text.strip() for lbl in labels if "label-primary" not in (lbl.get_attribute("class") or "")]
            access_elements = [lbl.text.strip() for lbl in labels if "label-primary" in (lbl.get_attribute("class") or "")]
            access = access_elements[0] if access_elements else ""

            logging.info(f"[P{page_num} R{row_idx}] Opening: {title}")

            # -----------------
            # Open detail page
            # -----------------
            driver.execute_script("window.open(arguments[0], '_blank');", url)
            driver.switch_to.window(driver.window_handles[-1])
            time.sleep(random.uniform(3, 6))

            # Extract detail info
            info_divs = driver.find_elements(By.CSS_SELECTOR, "div.well.well-sm")
            date, author, risk_detail, local, remote, cve, cwe = [""] * 7

            for div in info_divs:
                text = div.text.strip()
                if not text:
                    continue
                if re.match(r"\d{4}\.\d{2}\.\d{2}", text):
                    date = text
                elif text.lower().startswith("credit"):
                    author = text.replace("Credit:", "").strip()
                elif text.lower().startswith("risk"):
                    risk_detail = text.replace("Risk:", "").strip()
                elif text.lower().startswith("local"):
                    local = text.replace("Local:", "").strip()
                elif text.lower().startswith("remote"):
                    remote = text.replace("Remote:", "").strip()
                elif text.lower().startswith("cve"):
                    cve = text.replace("CVE:", "").strip()
                elif text.lower().startswith("cwe"):
                    cwe = text.replace("CWE:", "").strip()

            logging.info(f"[P{page_num} R{row_idx}] Scraped -> "
                         f"Date={date}, Author={author}, Risk={risk_detail}, "
                         f"Local={local}, Remote={remote}, CVE={cve}, CWE={cwe}")

            # Close detail tab and switch back
            try:
                driver.close()
            except:
                pass
            driver.switch_to.window(driver.window_handles[0])

            # Save row immediately to CSV
            row_data = {
                "Risk": risk_detail if risk_detail else risk,
                "Title": title,
                "URL": url,
                "Tags": ", ".join(tags),
                "Access": access,
                "Author": author,
                "Local": local,
                "Remote": remote,
                "CVE": cve,
                "CWE": cwe
            }
            append_to_csv(row_data)

            # Mark URL as processed
            processed_urls.add(url)

            # Save progress
            save_progress(page_num, row_idx)

            # Random delay between rows
            time.sleep(random.uniform(3, 6))

        except Exception as e:
            logging.error(f"Error processing row {row_idx} on page {page_num}: {e}")
            try:
                if len(driver.window_handles) > 1:
                    driver.close()
                    driver.switch_to.window(driver.window_handles[0])
            except:
                pass
            continue

# ----------------------
# Main loop with "Next" button
# ----------------------
try:
    while True:
        logging.info(f"Scraping index page {page_num}")
        scrape_page(page_num, start_from=start_row)

        # Reset row start after first page
        start_row = 1

        # ----------------------
        # Click "Next" if available
        # ----------------------
        try:
            next_button = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.XPATH, "//a[normalize-space(text())='Next']"))
            )
            driver.execute_script("arguments[0].click();", next_button)
            logging.info("Clicked Next button, moving to next page...")
            time.sleep(random.uniform(4, 8))  # allow page to load
            page_num += 1
        except Exception as e:
            logging.warning(f"No Next button found or not clickable (end of pages). Stopping. Error: {e}")

except KeyboardInterrupt:
    logging.info("Interrupted by user. Quitting...")
finally:
    logging.info(f"Scraping complete. Total entries collected: {len(processed_urls)}")
    try:
        driver.quit()
    except:
        pass
