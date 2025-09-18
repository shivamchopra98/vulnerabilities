import os
import csv
import time
import random
import logging
from urllib.parse import urljoin

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# ---------------------- Configuration ----------------------
BASE_INDEX = "https://packetstorm.news/files/exploit/{}"  # {page_num}
BASE_SITE = "https://packetstorm.news"
CHROME_DRIVER_PATH = r"C:\Users\ShivamChopra\Downloads\chromedriver-win64\chromedriver.exe"

OUTPUT_DIR = r"C:\Users\ShivamChopra\Projects\vulnerabilities\packetstorm_database"
os.makedirs(OUTPUT_DIR, exist_ok=True)
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "packetstorm_DB.csv")
LAST_PAGE_FILE = os.path.join(OUTPUT_DIR, "last_page.txt")
PROCESSED_FILE = os.path.join(OUTPUT_DIR, "processed_urls.txt")

CSV_HEADERS = ["Title", "URL", "Posted", "Format", "Size", "Authors", "Tags", "Site", "CVE", "Description"]

# If you know total pages you can set this; otherwise script stops when no links are found.
TOTAL_PAGES = 2230

# ---------------------- Timing (max delays <= 15s) ----------------------
INDEX_PAGE_DELAY_MIN = 3.0
INDEX_PAGE_DELAY_MAX = 15.0
DETAIL_PAGE_DELAY_MIN = 3.0
DETAIL_PAGE_DELAY_MAX = 15.0
SMALL_ACTION_DELAY_MIN = 0.8
SMALL_ACTION_DELAY_MAX = 2.2

# Anti-bot keywords (simple check)
ANTIBOT_KEYWORDS = ["unusual", "detected unusual", "access denied", "cloudflare", "bot verification", "are you human"]

# ---------------------- Logging ----------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ---------------------- Chrome driver setup ----------------------
chrome_options = Options()
# chrome_options.add_argument("--headless=new")  # visible is safer vs detection
chrome_options.add_argument("--disable-gpu")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")
chrome_options.add_argument("--start-maximized")
chrome_options.add_argument(
    "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

service = Service(CHROME_DRIVER_PATH)
driver = webdriver.Chrome(service=service, options=chrome_options)
wait = WebDriverWait(driver, 20)

# ---------------------- Resume helpers ----------------------
processed_urls = set()
if os.path.exists(PROCESSED_FILE):
    with open(PROCESSED_FILE, "r", encoding="utf-8") as f:
        for line in f:
            u = line.strip()
            if u:
                processed_urls.add(u)
    logging.info(f"Loaded {len(processed_urls)} previously processed URLs.")

start_page = 1
if os.path.exists(LAST_PAGE_FILE):
    try:
        with open(LAST_PAGE_FILE, "r", encoding="utf-8") as f:
            start_page = int(f.read().strip() or 1)
            logging.info(f"Resuming from saved page {start_page}")
    except Exception:
        start_page = 1

# ---------------------- CSV helper ----------------------
def append_to_csv(row):
    file_exists = os.path.exists(OUTPUT_CSV)
    with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADERS)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

def mark_processed(url):
    processed_urls.add(url)
    with open(PROCESSED_FILE, "a", encoding="utf-8") as f:
        f.write(url + "\n")

def save_last_page(page):
    with open(LAST_PAGE_FILE, "w", encoding="utf-8") as f:
        f.write(str(page))

# ---------------------- Human-like helper ----------------------
def human_like_pause(min_delay=1.0, max_delay=4.0):
    """
    Pause while doing small scroll-ups/downs repeatedly to look human.
    Max delay provided by caller must be <= 15s.
    """
    delay = random.uniform(min_delay, max_delay)
    # Do small scroll steps about every ~3 seconds (or less if delay short)
    start = time.time()
    while time.time() - start < delay:
        try:
            # small downward scroll
            scroll_down = random.randint(150, 450)
            driver.execute_script(f"window.scrollBy(0, {scroll_down});")
        except Exception:
            pass
        # sleep about 3s or remaining time
        sleep_chunk = min(3.0, delay - (time.time() - start))
        if sleep_chunk > 0:
            time.sleep(sleep_chunk)
        try:
            # small upward scroll
            driver.execute_script("window.scrollBy(0, -200);")
        except Exception:
            pass
        # tiny pause before next small scroll
        time.sleep(random.uniform(0.3, 1.0))
    # final small random jitter
    time.sleep(random.uniform(0.2, 0.8))

# ---------------------- Utility: collect index links ----------------------
def collect_exploit_links_on_index():
    """
    Returns a deduplicated list of full URLs found on the current index page.
    We target 'div.retro a' (desktop) and also check mobile/title variants.
    """
    links = []
    try:
        # Wait for at least one expected element (title blocks)
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "div.retro a, div.fretrot a")))
    except Exception:
        return []

    # small human-like activity before collecting
    human_like_pause(1.0, 3.0)

    anchor_elems = driver.find_elements(By.CSS_SELECTOR, "div.retro a, div.fretrot a, div.fretrotmob a")
    for a in anchor_elems:
        try:
            href = a.get_attribute("href")
            if href:
                full = href if href.startswith("http") else urljoin(BASE_SITE, href)
                links.append(full)
        except Exception:
            continue

    # dedupe while preserving order
    seen = set()
    dedup = []
    for l in links:
        if l not in seen:
            seen.add(l)
            dedup.append(l)
    return dedup

# ---------------------- Utility: extract detail metadata + description only ----------------------
def extract_detail_data():
    """
    Assumes driver is on the detail page for the exploit.
    Extracts metadata from the metadata table (div.rfsmall table rows)
    and the description in div.rfmedium. Returns a dict.
    """
    data = {"Posted": "", "Format": "", "Size": "", "Authors": "", "Tags": "", "Site": "", "CVE": "", "Description": ""}
    try:
        # metadata rows under the main container table
        rows = driver.find_elements(By.CSS_SELECTOR, "div.maincontainer div.rfsmall table tbody tr")
        if not rows:
            rows = driver.find_elements(By.CSS_SELECTOR, "div.rfsmall table tbody tr")
        for tr in rows:
            try:
                tds = tr.find_elements(By.TAG_NAME, "td")
                if len(tds) < 2:
                    continue
                key = tds[0].text.strip().rstrip(':').lower()
                if key == "posted":
                    data["Posted"] = tds[1].text.strip()
                elif key == "format":
                    data["Format"] = tds[1].text.strip()
                elif key == "size":
                    data["Size"] = tds[1].text.strip()
                elif "source" in key:
                    authors = [a.text.strip() for a in tds[1].find_elements(By.TAG_NAME, "a")]
                    data["Authors"] = ", ".join([x for x in authors if x])
                elif "tag" in key:
                    tags = [a.text.strip() for a in tds[1].find_elements(By.TAG_NAME, "a")]
                    data["Tags"] = ", ".join([x for x in tags if x])
                elif "site" in key:
                    data["Site"] = tds[1].text.strip()
                elif "cve" in key:
                    cves = [a.text.strip() for a in tds[1].find_elements(By.TAG_NAME, "a")]
                    data["CVE"] = ", ".join([x for x in cves if x])
            except Exception:
                continue
    except Exception:
        pass

    # Description - pick the rfmedium div (this contains the short description before content)
    try:
        desc_elem = driver.find_element(By.CSS_SELECTOR, "div.rfmedium")
        data["Description"] = desc_elem.text.strip()
    except Exception:
        try:
            desc_elem = driver.find_element(By.CSS_SELECTOR, "div.fretromob, div.fretrot")
            data["Description"] = desc_elem.text.strip()
        except Exception:
            data["Description"] = ""

    return data

# ---------------------- Simple anti-bot check ----------------------
def looks_like_antibot():
    try:
        body_text = driver.find_element(By.TAG_NAME, "body").text.lower()
        for kw in ANTIBOT_KEYWORDS:
            if kw in body_text:
                logging.warning(f"Anti-bot keyword detected on page: {kw}")
                return True
        return False
    except Exception:
        return False

# ---------------------- Main scraping loop ----------------------
try:
    page_num = start_page
    consecutive_empty_pages = 0

    while page_num <= TOTAL_PAGES:
        index_url = BASE_INDEX.format(page_num)
        logging.info(f"Loading index page {page_num}: {index_url}")
        try:
            driver.get(index_url)
        except Exception as e:
            logging.error(f"Driver.get failed for {index_url}: {e}")
            human_like_pause(3.0, 6.0)
            continue

        # allow page to render with human-like pause (max 15s)
        human_like_pause(INDEX_PAGE_DELAY_MIN, INDEX_PAGE_DELAY_MAX)

        # quick anti-bot check
        if looks_like_antibot():
            logging.warning("Anti-bot text detected on index page. Backing off briefly.")
            human_like_pause(8.0, 15.0)
            # try to continue after brief backoff
            continue

        # collect details links on this index page
        links = collect_exploit_links_on_index()
        logging.info(f"Found {len(links)} exploit links on page {page_num}")

        if not links:
            consecutive_empty_pages += 1
            if consecutive_empty_pages >= 3:
                logging.info("Several consecutive empty index pages — assuming end of listing. Stopping.")
                break
            else:
                logging.info("Empty page encountered, moving to next page.")
                page_num += 1
                save_last_page(page_num)
                human_like_pause(2.0, 5.0)
                continue
        else:
            consecutive_empty_pages = 0

        # iterate through the links (using hrefs, avoid stale elems)
        for link in links:
            # small sanitize: ignore links that are not id pages
            if "/files/id/" not in link:
                continue

            if link in processed_urls:
                logging.info(f"[P{page_num}] already processed {link} — skipping")
                continue

            logging.info(f"[P{page_num}] Opening detail: {link}")
            try:
                # open detail in new tab
                driver.execute_script("window.open(arguments[0], '_blank');", link)
                driver.switch_to.window(driver.window_handles[-1])

                # human-like pause on detail page (max 15s)
                human_like_pause(DETAIL_PAGE_DELAY_MIN, DETAIL_PAGE_DELAY_MAX)

                # anti-bot check on detail
                if looks_like_antibot():
                    logging.warning("Anti-bot detected on detail page. Closing and backing off briefly.")
                    try:
                        driver.close()
                        driver.switch_to.window(driver.window_handles[0])
                    except Exception:
                        pass
                    human_like_pause(8.0, 15.0)
                    continue

                # extract metadata + description
                detail = extract_detail_data()

                # title is visible on the page in the header; try to capture it
                try:
                    title_elem = driver.find_element(By.CSS_SELECTOR, "div.fretrot table td, div.fretrotmob table td")
                    title_text = title_elem.text.strip()
                except Exception:
                    try:
                        title_text = driver.find_element(By.CSS_SELECTOR, "div.retro a, h1").text.strip()
                    except Exception:
                        title_text = ""

                row = {
                    "Title": title_text or "",
                    "URL": link,
                    "Posted": detail.get("Posted", ""),
                    "Format": detail.get("Format", ""),
                    "Size": detail.get("Size", ""),
                    "Authors": detail.get("Authors", ""),
                    "Tags": detail.get("Tags", ""),
                    "Site": detail.get("Site", ""),
                    "CVE": detail.get("CVE", ""),
                    "Description": detail.get("Description", "")
                }

                # append to CSV and mark processed
                append_to_csv(row)
                mark_processed(link)
                logging.info(f"Saved: {row['Title'][:80]} ...")

            except Exception as e:
                logging.error(f"Error while processing detail {link}: {e}")
            finally:
                # close detail tab and switch back to index
                try:
                    if len(driver.window_handles) > 1:
                        driver.close()
                        driver.switch_to.window(driver.window_handles[0])
                except Exception:
                    try:
                        driver.switch_to.window(driver.window_handles[0])
                    except Exception:
                        pass

            # polite short delay between detail pages (max ~15s)
            human_like_pause(SMALL_ACTION_DELAY_MIN, SMALL_ACTION_DELAY_MAX)

        # update last page and move on
        save_last_page(page_num)
        page_num += 1

        # polite small pause between index pages (max 15s)
        human_like_pause(INDEX_PAGE_DELAY_MIN, INDEX_PAGE_DELAY_MAX)

    logging.info("Finished scraping (page loop ended).")

except KeyboardInterrupt:
    logging.info("Interrupted by user (KeyboardInterrupt).")
finally:
    logging.info(f"Scraping stopped. Processed URLs: {len(processed_urls)}")
    try:
        driver.quit()
    except Exception:
        pass
