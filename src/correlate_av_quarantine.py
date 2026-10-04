import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

AV_FILE = BASE_DIR / "output" / "av_remediation_events.csv"
QUARANTINE_FILE = BASE_DIR / "output" / "malicious_quarantine_detailed.csv"

# ============================================================
# LOAD DATA
# ============================================================

av = pd.read_csv(AV_FILE)
quarantine = pd.read_csv(QUARANTINE_FILE)

av["event_time"] = pd.to_datetime(av["event_time"])
quarantine["event_time"] = pd.to_datetime(quarantine["event_time"])

# ============================================================
# KEEP ACTUAL QUARANTINE ACTIONS
# ============================================================

av_actions = av[
    av["action"] == "quarantined_deleted"
].copy()

# Extract filename from original path
av_actions["filename"] = (
    av_actions["original_file"]
    .astype(str)
    .str.replace("\\", "/", regex=False)
    .str.split("/")
    .str[-1]
)

# ============================================================
# MATCH AV ACTIONS TO QUARANTINE INVENTORY
# ============================================================

matches = []

for _, av_row in av_actions.iterrows():

    endpoint = av_row["endpoint_id"]
    av_time = av_row["event_time"]
    filename = av_row["filename"]

    candidates = quarantine[
        (quarantine["endpoint_id"] == endpoint) &
        (quarantine["quarantine_file"].astype(str) == filename)
    ].copy()

    if candidates.empty:
        continue

    candidates["time_difference_seconds"] = (
        candidates["event_time"] - av_time
    ).dt.total_seconds()

    # Look for inventory records within 48 hours
    candidates = candidates[
        candidates["time_difference_seconds"].abs() <= 48 * 3600
    ]

    for _, q in candidates.iterrows():

        matches.append({
            "endpoint_id": endpoint,
            "filename": filename,
            "av_time": av_time,
            "quarantine_time": q["event_time"],
            "time_difference_seconds":
                q["event_time"] - av_time,
            "sha256": q["sha256"],
            "original_file": av_row["original_file"]
        })

# ============================================================
# RESULTS
# ============================================================

result = pd.DataFrame(matches)

print("=" * 90)
print("AV -> QUARANTINE CORRELATION")
print("=" * 90)

if result.empty:

    print("No AV-to-quarantine matches found.")

else:

    print(
        f"Matches found: {len(result)}"
    )

    print()

    for endpoint, group in result.groupby("endpoint_id"):

        print("-" * 90)
        print(f"ENDPOINT: {endpoint}")

        for _, row in group.iterrows():

            diff = row["time_difference_seconds"].total_seconds()

            if diff < 0:
                relation = "QUARANTINE BEFORE AV ACTION"
            elif diff > 0:
                relation = "QUARANTINE AFTER AV ACTION"
            else:
                relation = "SAME TIME"

            print(
                f"File: {row['filename']}"
            )

            print(
                f"  AV action:       {row['av_time']}"
            )

            print(
                f"  Quarantine:      {row['quarantine_time']}"
            )

            print(
                f"  Difference:      {abs(diff):.0f} seconds"
            )

            print(
                f"  Relation:        {relation}"
            )

            print(
                f"  SHA256:          {row['sha256']}"
            )

            print()

# ============================================================
# SAVE
# ============================================================

output_file = (
    BASE_DIR /
    "output" /
    "av_quarantine_correlation.csv"
)

result.to_csv(
    output_file,
    index=False
)

print("=" * 90)
print("SAVED")
print("=" * 90)

print(output_file)