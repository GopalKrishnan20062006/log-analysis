from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"

INPUT_FILE = OUTPUT_DIR / "malicious_quarantine_detailed.csv"
OUTPUT_FILE = OUTPUT_DIR / "malicious_file_classification.csv"

print("=" * 70)
print("STEP 11 - MALICIOUS FILE CLASSIFICATION")
print("=" * 70)

# ---------------------------------------------------------
# 1. Load malicious quarantine records
# ---------------------------------------------------------

df = pd.read_csv(INPUT_FILE)

# ---------------------------------------------------------
# 2. Extract filename
# ---------------------------------------------------------

df["filename"] = (
    df["quarantine_file"]
    .astype(str)
    .str.strip()
)

# ---------------------------------------------------------
# 3. Classify files
# ---------------------------------------------------------

def classify_file(filename):

    name = filename.lower()

    # Browser/payment related JavaScript
    if (
        ".js" in name
        or "wallet" in name
        or "checkout" in name
        or "payment" in name
        or "bnpl" in name
    ):
        return "Browser/Payment JavaScript"

    # Office/document files
    if any(
        ext in name
        for ext in [
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
            ".pdf"
        ]
    ):
        return "Document"

    # Archives
    if any(
        ext in name
        for ext in [
            ".zip",
            ".rar",
            ".7z",
            ".tar",
            ".gz",
            "compressed"
        ]
    ):
        return "Archive/Compressed"

    # Executables
    if any(
        ext in name
        for ext in [
            ".exe",
            ".dll",
            ".so",
            ".cab"
        ]
    ):
        return "Executable/Library"

    # Desktop launchers
    if ".desktop" in name:
        return "Desktop Launcher"

    # Shell/scripts
    if any(
        ext in name
        for ext in [
            ".sh",
            ".bash",
            ".py",
            ".pl"
        ]
    ):
        return "Script"

    # Browser history/recent files
    if (
        "recently-used" in name
        or "recent" in name
    ):
        return "Browser/Recent Activity"

    # Generic suspicious names
    return "Other"


df["file_category"] = df["filename"].apply(
    classify_file
)

# ---------------------------------------------------------
# 4. Create endpoint-level classification
# ---------------------------------------------------------

endpoint_summary = (
    df.groupby(
        [
            "endpoint_id",
            "endpoint_name",
            "unit",
            "file_category"
        ],
        as_index=False
    )
    .agg(
        malicious_records=("sha256", "size"),
        unique_hashes=("sha256", "nunique"),
        unique_files=("filename", "nunique"),
        first_detection=("event_time", "min"),
        last_detection=("event_time", "max")
    )
)

# ---------------------------------------------------------
# 5. Save
# ---------------------------------------------------------

endpoint_summary.to_csv(
    OUTPUT_FILE,
    index=False
)

# ---------------------------------------------------------
# 6. Overall category summary
# ---------------------------------------------------------

category_summary = (
    df.groupby(
        "file_category",
        as_index=False
    )
    .agg(
        malicious_records=("sha256", "size"),
        unique_hashes=("sha256", "nunique"),
        affected_endpoints=("endpoint_id", "nunique"),
        unique_files=("filename", "nunique")
    )
    .sort_values(
        "malicious_records",
        ascending=False
    )
)

print("\n" + "=" * 70)
print("FILE CATEGORY SUMMARY")
print("=" * 70)

print(
    category_summary.to_string(index=False)
)

# ---------------------------------------------------------
# 7. Show every endpoint with its classification
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("ENDPOINT CLASSIFICATION")
print("=" * 70)

for endpoint_id, group in endpoint_summary.groupby(
    "endpoint_id",
    sort=False
):

    first = group.iloc[0]

    categories = []

    for _, row in group.iterrows():

        categories.append(
            f"{row['file_category']} "
            f"({row['unique_files']} files, "
            f"{row['unique_hashes']} hashes)"
        )

    print(
        f"{endpoint_id} | "
        f"{first['endpoint_name']} | "
        f"{first['unit']} | "
        f"{' ; '.join(categories)}"
    )

print("\n" + "=" * 70)
print("SAVED")
print("=" * 70)

print(OUTPUT_FILE)