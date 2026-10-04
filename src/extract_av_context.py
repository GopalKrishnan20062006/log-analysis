import pandas as pd
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECURITY_FILE = BASE_DIR / "data" / "endpoint_security.csv"
OUTPUT_FILE = BASE_DIR / "output" / "av_remediation_events.csv"

# ============================================================
# LOAD DATA
# ============================================================

df = pd.read_csv(SECURITY_FILE)

df["event_time"] = pd.to_datetime(
    df["event_time"],
    format="%d-%m-%Y %H:%M:%S"
)

av = df[df["log_type"] == "av_scan"].copy()

# ============================================================
# IDENTIFY REAL AV ACTIONS
# ============================================================

patterns = {
    "infection_found":
        r"Infected files found\. Beginning quarantine",

    "processing":
        r"Processing:\s*'?(.*?)'?$",

    "attempting_handle":
        r"Attempting to handle:\s*(.*)",

    "quarantined_deleted":
        r"Quarantined and deleted:\s*(.*?)\s+to\s+(.*)",
}

results = []

for _, row in av.iterrows():

    message = str(row["message"])

    # --------------------------------------------------------
    # Infection found
    # --------------------------------------------------------

    if re.search(patterns["infection_found"], message, re.I):

        results.append({
            "endpoint_id": row["endpoint_id"],
            "event_time": row["event_time"],
            "action": "infection_found",
            "original_file": "",
            "quarantine_file": "",
            "message": message
        })

    # --------------------------------------------------------
    # Processing
    # --------------------------------------------------------

    match = re.search(
        patterns["processing"],
        message,
        re.I
    )

    if match:

        file_path = match.group(1).strip()

        results.append({
            "endpoint_id": row["endpoint_id"],
            "event_time": row["event_time"],
            "action": "processing",
            "original_file": file_path,
            "quarantine_file": "",
            "message": message
        })

    # --------------------------------------------------------
    # Attempting to handle
    # --------------------------------------------------------

    match = re.search(
        patterns["attempting_handle"],
        message,
        re.I
    )

    if match:

        file_path = match.group(1).strip()

        results.append({
            "endpoint_id": row["endpoint_id"],
            "event_time": row["event_time"],
            "action": "attempting_handle",
            "original_file": file_path,
            "quarantine_file": "",
            "message": message
        })

    # --------------------------------------------------------
    # Quarantined and deleted
    # --------------------------------------------------------

    match = re.search(
        patterns["quarantined_deleted"],
        message,
        re.I
    )

    if match:

        original_file = match.group(1).strip()
        quarantine_file = match.group(2).strip()

        results.append({
            "endpoint_id": row["endpoint_id"],
            "event_time": row["event_time"],
            "action": "quarantined_deleted",
            "original_file": original_file,
            "quarantine_file": quarantine_file,
            "message": message
        })

# ============================================================
# CREATE RESULT
# ============================================================

result = pd.DataFrame(results)

if result.empty:

    print("No genuine AV remediation events found.")

else:

    result = result.sort_values(
        ["endpoint_id", "event_time"]
    )

    print("=" * 80)
    print("GENUINE AV REMEDIATION EVENTS")
    print("=" * 80)

    print(
        f"Total remediation events: {len(result)}"
    )

    print()

    print(
        result["action"]
        .value_counts()
        .to_string()
    )

    print()
    print("=" * 80)
    print("ENDPOINTS WITH AV REMEDIATION")
    print("=" * 80)

    endpoint_summary = (
        result
        .groupby("endpoint_id")
        .agg(
            remediation_events=("action", "size"),
            first_av_action=("event_time", "min"),
            last_av_action=("event_time", "max")
        )
        .sort_values(
            "remediation_events",
            ascending=False
        )
    )

    print(endpoint_summary.to_string())

    print()
    print("=" * 80)
    print("DETAILED AV ACTIONS")
    print("=" * 80)

    for endpoint_id, group in result.groupby("endpoint_id"):

        print()
        print(f"ENDPOINT: {endpoint_id}")

        for _, row in group.iterrows():

            print(
                f"{row['event_time']} | "
                f"{row['action']} | "
                f"{row['original_file']}"
            )

    # ========================================================
    # SAVE
    # ========================================================

    result.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print()
    print("=" * 80)
    print("SAVED")
    print("=" * 80)

    print(OUTPUT_FILE)