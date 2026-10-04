import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = BASE_DIR / "output" / "malicious_quarantine_detailed.csv"
OUTPUT_DIR = BASE_DIR / "output"

# ============================================================
# LOAD DATA
# ============================================================

df = pd.read_csv(INPUT_FILE)

df["event_time"] = pd.to_datetime(df["event_time"])

# ============================================================
# SHOW UNIQUE MALICIOUS FILES BY ENDPOINT
# ============================================================

print("=" * 80)
print("UNIQUE MALICIOUS FILES BY ENDPOINT")
print("=" * 80)

# Keep one record per endpoint + file + hash
unique_files = (
    df[
        [
            "endpoint_id",
            "endpoint_name",
            "unit",
            "quarantine_file",
            "sha256",
            "event_time",
        ]
    ]
    .drop_duplicates(
        subset=["endpoint_id", "quarantine_file", "sha256"]
    )
    .sort_values(["endpoint_id", "event_time"])
)

for endpoint_id, group in unique_files.groupby("endpoint_id"):

    first = group.iloc[0]

    print()
    print(
        f"{endpoint_id} | "
        f"{first['endpoint_name']} | "
        f"{first['unit']}"
    )

    for _, row in group.iterrows():

        print(
            f"    File: {row['quarantine_file']}"
        )

        print(
            f"    SHA256: {row['sha256']}"
        )

        print(
            f"    First seen: "
            f"{row['event_time']}"
        )

        print()

# ============================================================
# SAVE UNIQUE FILE LIST
# ============================================================

output_file = OUTPUT_DIR / "unique_malicious_files.csv"

unique_files.to_csv(output_file, index=False)

print("=" * 80)
print("SAVED")
print("=" * 80)
print(output_file)
print(f"Unique endpoint/file/hash combinations: {len(unique_files)}")