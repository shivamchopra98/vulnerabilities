import os
import time
import csv
import re
from urllib.parse import urljoin
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
from tqdm import tqdm

# ---------- CONFIG ----------
BASE_URL = "https://malpedia.caad.fkie.fraunhofer.de"
ACTORS_INDEX = BASE_URL + "/actors"
OUT_DIR = r"C:\Users\ShivamChopra\Projects\vulnerabilities\malpedia_database"
OUT_CSV = "base_database.csv"
SLEEP_BETWEEN_REQUESTS = 1.0  # seconds between navigation calls
MAX_SIBLING_STEPS = 30       # how many siblings to collect after the "Associated Families" heading
# ----------------------------

# Selenium setup (visible browser)
chrome_options = Options()
chrome_options.headless = False
chrome_options.add_argument("--start-maximized")
driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)


def fsync_file(fobj):
    """Force an OS-level flush so other programs (like Excel) can see updates."""
    try:
        fobj.flush()
        os.fsync(fobj.fileno())
    except Exception:
        # best-effort; some platforms / editors still won't auto-refresh
        pass


def extract_aka_aliases(soup):
    # Prefer the info icon attribute if present
    info_i = soup.select_one("td.info_synonyms i")
    if info_i and info_i.has_attr("data-original-title"):
        return info_i["data-original-title"].strip()
    # fallback: hidden synonyms <td class="synonyms">
    syn_td = soup.find("td", class_="synonyms")
    if syn_td:
        return syn_td.get_text(separator=", ", strip=True)
    # fallback: search for text nodes starting with 'aka:'
    text_nodes = soup.find_all(text=re.compile(r"^aka\s*:", re.I))
    if text_nodes:
        # get the immediate parent text
        return text_nodes[0].strip()
    return ""


def extract_description(soup, aka_aliases=""):
    # meta description
    meta = soup.find("meta", attrs={"name": "description"})
    narrative = ""
    if meta and meta.get("content"):
        narrative = meta["content"].strip()
    else:
        # common Malpedia slots: panel-body, lead, or paragraph after h1
        div_body = soup.find("div", class_="panel-body")
        if div_body:
            narrative = div_body.get_text(" ", strip=True)
        else:
            div_lead = soup.find("div", class_="lead")
            if div_lead:
                narrative = div_lead.get_text(" ", strip=True)
            else:
                h1 = soup.find("h1")
                if h1:
                    p = h1.find_next("p")
                    if p:
                        narrative = p.get_text(" ", strip=True)
    if aka_aliases:
        return f"aka: {aka_aliases}\n\n{narrative}"
    return narrative


def extract_families(soup):
    """
    Robust extraction:
    - Find the heading containing "Associated Families" (case-insensitive).
    - Collect subsequent siblings (text, <p>, <div>, <ul>) until next header or step limit.
    - Split the collected block by whitespace and select tokens that look like family names.
    - Return a comma-separated string of unique families (preserving original order).
    """
    families = []
    # Find headings (h1..h6) and find the one that includes "associated family" or "associated families"
    headings = soup.find_all(re.compile(r"^h[1-6]$", re.IGNORECASE))
    target_heading = None
    for h in headings:
        text = h.get_text(" ", strip=True).lower()
        if "associated family" in text or "associated families" in text:
            target_heading = h
            break

    if not target_heading:
        # Sometimes site uses small headings or different wording — try a broader search
        possible = soup.find_all(text=re.compile(r"associated\s+famil", re.I))
        if possible:
            # pick the parent header if available
            for node in possible:
                parent = node.parent
                if parent and re.match(r"^h[1-6]$", parent.name or "", re.I):
                    target_heading = parent
                    break

    if target_heading:
        sib = target_heading.find_next_sibling()
        steps = 0
        text_acc = []
        while sib and steps < MAX_SIBLING_STEPS:
            # stop if next header
            if sib.name and re.match(r"^h[1-6]$", sib.name, re.IGNORECASE):
                break
            # get textual content of relevant nodes
            if sib.name in ("p", "div", "ul", "ol"):
                t = sib.get_text(" ", strip=True)
                if t:
                    text_acc.append(t)
            else:
                # Sometimes there are NavigableString or other inline nodes
                txt = getattr(sib, "string", None)
                if txt:
                    txt = txt.strip()
                    if txt:
                        text_acc.append(txt)
            sib = sib.find_next_sibling()
            steps += 1

        # join all collected text and split by whitespace
        joined = " ".join(text_acc)
        # Malpedia family names often contain letters/numbers/dot/underscore/hyphen
        tokens = re.split(r"\s+", joined.strip())
        family_pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")  # conservative
        seen = set()
        ordered = []
        for tok in tokens:
            tok_clean = tok.strip()
            if not tok_clean:
                continue
            # filter out words like "Associated" "Families" "References" etc.
            if family_pattern.match(tok_clean):
                lc = tok_clean.lower()
                if lc not in seen:
                    seen.add(lc)
                    ordered.append(tok_clean)
        families = ordered

    # If none found yet, attempt to find <a href="/family/"> links as fallback
    if not families:
        for a in soup.find_all("a", href=True):
            if re.match(r"^/family/", a["href"]):
                name = a.get_text(strip=True)
                if name:
                    if name.lower() not in [f.lower() for f in families]:
                        families.append(name)

    # final dedupe preserving order already done
    return ", ".join(families)


def parse_index_page_and_collect_actors():
    """Load the index page and return a list of actor dicts with common_name, aliases(if any), country, href."""
    driver.get(ACTORS_INDEX)
    time.sleep(2)
    soup = BeautifulSoup(driver.page_source, "lxml")
    rows = soup.select("tr.clickable-row")
    actors = []
    for r in rows:
        data_href = r.get("data-href") or ""
        full_link = urljoin(BASE_URL, data_href)
        common_td = r.find("td", class_="common_name")
        common_name = common_td.get_text(strip=True) if common_td else ""
        # aliases present in the row as hidden; we'll also fetch aliases from actor page
        aliases = ""
        info_i = r.select_one("td.info_synonyms i")
        if info_i and info_i.has_attr("data-original-title"):
            aliases = info_i["data-original-title"].strip()
        # country
        country = ""
        flag = r.select_one("td.country span.flag-icon")
        if flag:
            classes = flag.get("class", [])
            for c in classes:
                if c.startswith("flag-icon-") and c != "flag-icon":
                    country = c.replace("flag-icon-", "").strip()
                    break
        actors.append({
            "common_name": common_name,
            "aliases": aliases,
            "country": country,
            "href": full_link
        })
    return actors


def scrape():
    Path(OUT_DIR).mkdir(parents=True, exist_ok=True)
    out_path = os.path.join(OUT_DIR, OUT_CSV)

    actors = parse_index_page_and_collect_actors()
    print(f"Found {len(actors)} actors on index.")

    fieldnames = ["common_name", "aliases", "country", "actor_url", "description", "associated_families"]
    with open(out_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        fsync_file(csvfile)

        for actor in tqdm(actors, desc="Actors"):
            actor_url = actor.get("href")
            if not actor_url:
                continue

            try:
                driver.get(actor_url)
                time.sleep(SLEEP_BETWEEN_REQUESTS)
                soup = BeautifulSoup(driver.page_source, "lxml")

                # aliases: prefer actor page content (more complete)
                aka_aliases = extract_aka_aliases(soup)
                aliases = aka_aliases or actor.get("aliases", "")

                description = extract_description(soup, aka_aliases)
                families_str = extract_families(soup)  # comma-separated

                # Build the row — write even if families_str is empty (so CSV shows progress)
                row = {
                    "common_name": actor.get("common_name", ""),
                    "aliases": aliases,
                    "country": actor.get("country", ""),
                    "actor_url": actor_url,
                    "description": description,
                    "associated_families": families_str
                }

                writer.writerow(row)
                fsync_file(csvfile)  # ensure disk write

                # compute number of families (0 if empty)
                num_fams = 0
                if families_str:
                    num_fams = len([f for f in families_str.split(",") if f.strip()])
                # console summary
                snippet = (description[:140].replace("\n", " ") + "...") if description else ""
                print(f"[EXTRACTED] {row['common_name']} | Families: {num_fams} | Country: {row['country']} | Desc-snippet: {snippet}")

            except Exception as e:
                print(f"[ERROR] {actor.get('common_name', 'Unknown')} -> {e}")

    print("Done. CSV saved to:", out_path)
    driver.quit()


if __name__ == "__main__":
    scrape()
