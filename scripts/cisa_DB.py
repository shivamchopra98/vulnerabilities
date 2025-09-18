from pathlib import Path
import requests
import shutil
import sys
import pandas as pd
from datetime import datetime

# --- USER CONFIG ---
CSV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
BASE_DIR = Path(r"C:\Users\ShivamChopra\Projects\vulnerabilities\cisa_database")
BASE_FILE = BASE_DIR / "base_database.csv"
# --------------------

TIMEOUT = 20
CHUNK_SIZE = 8192


def download_file(url: str, dest: Path, timeout: int = TIMEOUT) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)

    with requests.get(url, stream=True, timeout=timeout) as r:
        r.raise_for_status()

        tmp_path = dest.with_suffix(dest.suffix + ".part")
        with tmp_path.open("wb") as f:
            for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
                if chunk:
                    f.write(chunk)
            f.flush()

        shutil.move(str(tmp_path), str(dest))
        print(f"Saved CSV to: {dest}")


def update_base_database(new_file: Path, base_file: Path):
    # Load both CSVs
    new_df = pd.read_csv(new_file)
    if base_file.exists():
        base_df = pd.read_csv(base_file)
    else:
        print("Base database does not exist, creating a new one.")
        new_df.to_csv(base_file, index=False)
        return

    # Compare and append only new rows (by all columns)
    combined_df = pd.concat([base_df, new_df]).drop_duplicates(keep="first")

    # Save updated base file
    combined_df.to_csv(base_file, index=False)
    print(f"Updated base database with {len(combined_df) - len(base_df)} new rows.")

    # Delete the temp file
    new_file.unlink(missing_ok=True)
    print(f"Deleted temporary file: {new_file}")


if __name__ == "__main__":
    try:
        today = datetime.now().strftime("%Y-%m-%d")
        new_file = BASE_DIR / f"kev_{today}.csv"

        print(f"Downloading KEV CSV from:\n  {CSV_URL}")
        download_file(CSV_URL, new_file)

        print("Updating base database...")
        update_base_database(new_file, BASE_FILE)

    except requests.Timeout:
        print("Download timed out. Try increasing TIMEOUT or check your network.")
        sys.exit(2)
    except requests.RequestException as e:
        print(f"Network error: {e}")
        sys.exit(3)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(4)
