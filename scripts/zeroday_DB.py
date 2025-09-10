from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import pandas as pd
import os
import time

# ------------------- Selenium Setup -------------------
chrome_options = Options()
chrome_options.add_argument("--disable-gpu")
# chrome_options.add_argument("--headless")  # Uncomment when stable
service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service, options=chrome_options)
driver.maximize_window()

# ------------------- Open Main Database -------------------
print("🌍 Opening database page...")
driver.get("https://www.zero-day.cz/database/")
time.sleep(3)

# ------------------- Scroll to Load All Entries -------------------
print("📜 Scrolling to load all entries...")
last_height = driver.execute_script("return document.body.scrollHeight")
while True:
    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
    time.sleep(2)
    new_height = driver.execute_script("return document.body.scrollHeight")
    if new_height == last_height:
        break
    last_height = new_height
print("✅ Finished scrolling. All entries should be loaded.")

# ------------------- Step 1: Collect Main Page Data -------------------
cve_list = []
vuln_blocks = driver.find_elements(By.CSS_SELECTOR, "div.issue")
print(f"🔎 Found {len(vuln_blocks)} entries on main page.")

for idx, block in enumerate(vuln_blocks, start=1):
    try:
        a_tag = block.find_element(By.CSS_SELECTOR, "h3.issue-title a")
        title_lines = [t.strip() for t in a_tag.text.split('\n') if "CVE" not in t]
        title = " ".join(title_lines)

        try:
            cve = block.find_element(By.CSS_SELECTOR, "h3.issue-title span.issue-code").text.strip()
        except:
            cve = ""

        # Dates
        try:
            discovered = block.find_element(By.CSS_SELECTOR, "div.discavered time").text.strip()
        except:
            discovered = ""
        try:
            patched = block.find_element(By.CSS_SELECTOR, "div.patched time").text.strip()
        except:
            patched = ""

        detail_link = a_tag.get_attribute("href")
        if detail_link.startswith("/"):
            detail_link = "https://www.zero-day.cz" + detail_link

        cve_list.append({
            "Title": title,
            "CVE": cve,
            "Discovered_Date": discovered,
            "Patched_Date": patched,
            "Detail_Link": detail_link
        })

    except Exception as e:
        print(f"⚠️ Skipping entry {idx} due to error: {e}")
        continue

# ------------------- Step 2: Visit Each Detail Page -------------------
entries = []
cve_set = set()

for idx, item in enumerate(cve_list, start=1):
    cve = item["CVE"]
    if not cve or cve in cve_set:
        continue
    cve_set.add(cve)

    print(f"➡️ Opening detail page for {cve} ({idx}/{len(cve_list)})")

    try:
        driver.get(item["Detail_Link"])
        time.sleep(2)

        # Full description
        try:
            desc_block = driver.find_element(By.CSS_SELECTOR, "div.description")
            description_detail = " ".join(desc_block.text.split())
        except:
            description_detail = ""

        advisory = ""
        vulnerable_component = ""
        cvss_score = ""
        cwe_id = ""
        external_links = ""

        try:
            detail_texts = driver.find_elements(By.CSS_SELECTOR, "div.description p, div.description div")
            for elem in detail_texts:
                text = elem.text.strip()
                if text.startswith("Advisory:"):
                    advisory = text.replace("Advisory:", "").strip()
                elif text.startswith("Vulnerable component:"):
                    vulnerable_component = text.replace("Vulnerable component:", "").strip()
                elif text.startswith("CVSSv3 score:"):
                    cvss_score = text.replace("CVSSv3 score:", "").strip()
                elif text.startswith("CWE-ID:"):
                    cwe_id = text.replace("CWE-ID:", "").strip()
        except:
            pass

        try:
            links = driver.find_elements(By.CSS_SELECTOR, "div.description a")
            external_links = "; ".join([link.get_attribute("href") for link in links if link.get_attribute("href")])
        except:
            pass

        entries.append({
            "Title": item["Title"],
            "CVE": cve,
            "Description": description_detail,
            "Discovered_Date": item["Discovered_Date"],
            "Patched_Date": item["Patched_Date"],
            "Advisory": advisory,
            "Vulnerable_Component": vulnerable_component,
            "CVSSv3": cvss_score,
            "CWE_ID": cwe_id,
            "External_Links": external_links
        })

        print(f"✅ Extracted {cve}")

    except Exception as e:
        print(f"⚠️ Skipping {cve} due to error: {e}")
        continue

# ------------------- Close Browser -------------------
driver.quit()

# ------------------- Save CSV -------------------
folder_path = r"C:\Users\ShivamChopra\Projects\vulnerabilities\zeroday_database"
os.makedirs(folder_path, exist_ok=True)

csv_path = os.path.join(folder_path, "zeroday_DB.csv")
df = pd.DataFrame(entries)
df.to_csv(csv_path, index=False)
print(f"\n💾 Saved {len(df)} entries to {csv_path}")
