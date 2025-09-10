# import os
# import json
# import pandas as pd

# # -----------------------------
# # Input/Output paths
# # -----------------------------
# INPUT_FILE = r"C:\Users\ShivamChopra\Projects\vulnerabilities\core-labs-exploits-2025-09-09(1).json"
# OUTPUT_FILE = INPUT_FILE.replace(".json", ".csv")


# def extract_english_description(desc_list):
#     """Return only the English description string from the descriptions list."""
#     if not isinstance(desc_list, list):
#         return ""
#     for d in desc_list:
#         if isinstance(d, dict) and d.get("lang") == "en":
#             return d.get("value", "")
#     return ""


# def flatten_json(file_path):
#     """Flatten JSON file into a DataFrame, handling both dict and list root formats."""
#     with open(file_path, "r", encoding="utf-8") as f:
#         data = json.load(f)

#     # Case 1: Top-level dict (NVD style)
#     if isinstance(data, dict):
#         vulns = data.get("vulnerabilities") or data.get("cve_items") or data.get("CVE_Items") or []
#         if not vulns:
#             return pd.DataFrame()

#         if isinstance(vulns[0], dict) and "cve" in vulns[0]:
#             cve_records = [v.get("cve", {}) for v in vulns]
#         else:
#             cve_records = vulns

#     # Case 2: Top-level list
#     elif isinstance(data, list):
#         cve_records = data

#     else:
#         print("⚠️ Unsupported JSON format.")
#         return pd.DataFrame()

#     # Flatten with pandas
#     df = pd.json_normalize(cve_records, sep="_")

#     if "descriptions" in df.columns:
#         df["descriptions"] = df["descriptions"].apply(extract_english_description)

#     return df


# def main():
#     print(f"Processing {INPUT_FILE} ...")
#     df = flatten_json(INPUT_FILE)

#     if not df.empty:
#         df.to_csv(OUTPUT_FILE, index=False, encoding="utf-8")
#         print(f"✅ Exported {len(df)} CVEs with {len(df.columns)} columns → {OUTPUT_FILE}")
#     else:
#         print("⚠️ No CVEs found to export.")


# if __name__ == "__main__":
#     main()
