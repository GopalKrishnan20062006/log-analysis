from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output"

OUTPUT_DIR.mkdir(exist_ok=True)

SECURITY_FILE = DATA_DIR / "endpoint_security.csv"

DATETIME_FORMAT = "%d-%m-%Y %H:%M:%S"

print("=" * 70)
print("ANALYZING MALICIOUS QUARANTINE RECORDS")
print("=" * 70)

# ---------------------------------------------------------
# LOAD DATA
# ---------------------------------------------------------

df = pd.read_csv(SECURITY_FILE)

df["event_time"] = pd.to_datetime(
    df["event_time"],
    format=DATETIME_FORMAT,
    errors="coerce"
)

# ---------------------------------------------------------
# KEEP ONLY QUARANTINE EVENTS
# ---------------------------------------------------------

quarantine = df[
    df["log_type"] == "quarantine"
].copy()

print("Total quarantine rows:", len(quarantine))

# ---------------------------------------------------------
# IDENTIFY MALICIOUS FILE RECORDS
#
# A malicious quarantine record contains:
# FileType: Malicious
# ---------------------------------------------------------

malicious = quarantine[
    quarantine["message"]
    .astype(str)
    .str.contains(
        "FileType:\s*Malicious",
        case=False,
        regex=True,
        na=False
    )
].copy()

print("Malicious quarantine records:", len(malicious))

# ---------------------------------------------------------
# EXTRACT QUARANTINE FILE + SHA256
# ---------------------------------------------------------

malicious["quarantine_file"] = (
    malicious["message"]
    .astype(str)
    .str.extract(
        r"File:\s*(\S+)",
        expand=False
    )
)

malicious["sha256"] = (
    malicious["message"]
    .astype(str)
    .str.extract(
        r"SHA256:\s*([a-fA-F0-9]{64})",
        expand=False
    )
    .str.lower()
)

# ---------------------------------------------------------
# 1. ENDPOINT SUMMARY
# ---------------------------------------------------------

endpoint_summary = (
    malicious
    .groupby(
        [
            "endpoint_id",
            "endpoint_name",
            "unit"
        ]
    )
    .agg(
        malicious_records=("endpoint_id", "size"),
        unique_sha256s=("sha256", "nunique"),
        first_detection=("event_time", "min"),
        last_detection=("event_time", "max"),
        files=(
            "quarantine_file",
            lambda x: "; ".join(sorted(set(x.dropna())))
        )
    )
    .reset_index()
    .sort_values(
        "malicious_records",
        ascending=False
    )
)

print("\n" + "=" * 70)
print("ENDPOINTS WITH MALICIOUS QUARANTINE RECORDS")
print("=" * 70)

print(
    endpoint_summary.to_string(index=False)
)

print("\nUnique affected endpoints:",
      endpoint_summary["endpoint_id"].nunique())

# ---------------------------------------------------------
# 2. SHA256 SUMMARY
# ---------------------------------------------------------

hash_summary = (
    malicious
    .groupby("sha256")
    .agg(
        occurrence_count=("sha256", "size"),
        endpoints=("endpoint_id", "nunique"),
        endpoint_list=(
            "endpoint_id",
            lambda x: ", ".join(sorted(set(x)))
        ),
        files=(
            "quarantine_file",
            lambda x: "; ".join(sorted(set(x.dropna())))
        )
    )
    .reset_index()
    .sort_values(
        "occurrence_count",
        ascending=False
    )
)

print("\n" + "=" * 70)
print("MALICIOUS SHA256 SUMMARY")
print("=" * 70)

print(
    hash_summary.to_string(index=False)
)

# ---------------------------------------------------------
# 3. UNIT SUMMARY
# ---------------------------------------------------------

unit_summary = (
    malicious
    .groupby("unit")
    .agg(
        malicious_records=("endpoint_id", "size"),
        affected_endpoints=("endpoint_id", "nunique")
    )
    .reset_index()
    .sort_values(
        "affected_endpoints",
        ascending=False
    )
)

print("\n" + "=" * 70)
print("AFFECTED UNITS")
print("=" * 70)

print(
    unit_summary.to_string(index=False)
)

# ---------------------------------------------------------
# 4. SAVE RESULTS
# ---------------------------------------------------------

malicious.to_csv(
    OUTPUT_DIR / "malicious_quarantine_detailed.csv",
    index=False
)

endpoint_summary.to_csv(
    OUTPUT_DIR / "malicious_endpoint_summary.csv",
    index=False
)

hash_summary.to_csv(
    OUTPUT_DIR / "malicious_hash_summary.csv",
    index=False
)

unit_summary.to_csv(
    OUTPUT_DIR / "malicious_unit_summary.csv",
    index=False
)

print("\n" + "=" * 70)
print("FILES SAVED")
print("=" * 70)

print(OUTPUT_DIR / "malicious_quarantine_detailed.csv")
print(OUTPUT_DIR / "malicious_endpoint_summary.csv")
print(OUTPUT_DIR / "malicious_hash_summary.csv")
print(OUTPUT_DIR / "malicious_unit_summary.csv")