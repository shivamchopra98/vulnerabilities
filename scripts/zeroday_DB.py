from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
import pandas as pd
import os
import time

# ------------------- Setup -------------------
chrome_options = Options()
chrome_options.add_argument("--disable-gpu")
# chrome_options.add_argument("--headless=new")  # uncomment for headless mode
service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service, options=chrome_options)
driver.maximize_window()

# ------------------- File paths -------------------
folder_path = r"C:\Users\ShivamChopra\Projects\vulnerabilities\zeroday_database"
os.makedirs(folder_path, exist_ok=True)
csv_path = os.path.join(folder_path, "zeroday_DB.csv")

# ------------------- Load existing CSV or scrape new -------------------
if os.path.exists(csv_path):
    print("📂 Loading existing CSV...")
    df = pd.read_csv(csv_path)
else:
    print("🌍 Opening database page...")
    driver.get("https://www.zero-day.cz/database/")
    time.sleep(3)

    # Limited scrolling (to avoid crashes)
    print("📜 Scrolling to load entries...")
    for _ in range(20):  # scroll 20 times only
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(2)

    vuln_blocks = driver.find_elements(By.CSS_SELECTOR, "div.issue")
    print(f"🔎 Found {len(vuln_blocks)} entries on main page.")

    cve_list = []
    for idx, block in enumerate(vuln_blocks, start=1):
        try:
            a_tag = block.find_element(By.CSS_SELECTOR, "h3.issue-title a")
            title_lines = [t.strip() for t in a_tag.text.split('\n') if "CVE" not in t]
            title = " ".join(title_lines)

            try:
                cve = block.find_element(By.CSS_SELECTOR, "h3.issue-title span.issue-code").text.strip()
            except:
                cve = ""

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
                "Detail_Link": detail_link,
                "Description": "",
                "Advisory": "",
                "Vulnerable_Component": "",
                "CVSSv3": "",
                "CWE_ID": "",
                "External_Links": ""
            })

        except Exception as e:
            print(f"⚠️ Skipping entry {idx} due to error: {e}")
            continue

    df = pd.DataFrame(cve_list)
    df.to_csv(csv_path, index=False)
    print(f"💾 Initial data saved to {csv_path}")

# ------------------- Step 2: Fill Missing Descriptions -------------------
print("🔎 Fetching missing descriptions...")
for i, row in df.iterrows():
    if pd.notna(row["Description"]) and str(row["Description"]).strip() != "":
        continue  # already filled

    cve = row["CVE"]
    detail_link = row["Detail_Link"]
    if not isinstance(detail_link, str) or not detail_link.startswith("http"):
        continue

    print(f"\n➡️ Opening detail page for {cve} ({i+1}/{len(df)})")
    print(f"   📝 Title: {row['Title']}")
    print(f"   🛡️ CVE: {cve}")

    try:
        driver.get(detail_link)

        # collect all description blocks
        desc_blocks = driver.find_elements(By.CSS_SELECTOR, "div.description")
        description_detail = ""
        advisory = ""
        vulnerable_component = ""
        cvss_score = ""
        cwe_id = ""
        external_links = ""

        for block in desc_blocks:
            html = block.get_attribute("innerHTML")

            if "<b>Description" in html:
                text_parts = block.find_elements(By.TAG_NAME, "p")
                description_detail = " ".join([p.text.strip() for p in text_parts if p.text.strip()])
            if "<b>Advisory" in html:
                try:
                    advisory = block.find_element(By.TAG_NAME, "p").text.strip()
                except:
                    pass
            if "<b>Vulnerable component" in html:
                try:
                    vulnerable_component = block.find_element(By.TAG_NAME, "p").text.strip()
                except:
                    pass
            if "<b>CVSSv3" in html:
                try:
                    cvss_score = block.find_element(By.TAG_NAME, "p").text.strip()
                except:
                    pass
            if "<b>CWE-ID" in html:
                try:
                    cwe_id = block.find_element(By.TAG_NAME, "p").text.strip()
                except:
                    pass
            if "<b>External links" in html:
                links = block.find_elements(By.TAG_NAME, "a")
                external_links = "; ".join([link.get_attribute("href") for link in links if link.get_attribute("href")])

        # Update row
        df.at[i, "Description"] = description_detail
        df.at[i, "Advisory"] = advisory
        df.at[i, "Vulnerable_Component"] = vulnerable_component
        df.at[i, "CVSSv3"] = cvss_score
        df.at[i, "CWE_ID"] = cwe_id
        df.at[i, "External_Links"] = external_links

        # Log preview
        print(f"   📖 Description: {description_detail[:150]}...")
        print(f"   📌 Advisory: {advisory}")
        print(f"   🧩 Component: {vulnerable_component}")
        print(f"   🎯 CVSS: {cvss_score}")
        print(f"   🏷️ CWE: {cwe_id}")
        print(f"   🔗 Links: {external_links}")
        print(f"✅ Successfully extracted {cve}")

        # Save incrementally (clean before saving)
        def clean_text(text):
            if not isinstance(text, str):
                return text
            text = text.replace("\n", " ").replace("\r", " ").strip()
            if text.startswith(":"):
                text = text[1:].strip()
            return text

        for col in ["Description", "Advisory", "Vulnerable_Component", "CVSSv3", "CWE_ID", "External_Links"]:
            df[col] = df[col].apply(clean_text)

        df.to_csv(csv_path, index=False)

    except Exception as e:
        print(f"⚠️ Skipping {cve} due to error: {e}")
        continue

# ------------------- Close Browser -------------------
driver.quit()
print(f"\n💾 Final data saved to {csv_path}")
