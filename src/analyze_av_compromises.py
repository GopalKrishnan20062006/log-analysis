import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

AV_FILE = BASE_DIR / "output" / "av_remediation_events.csv"

# ============================================================
# LOAD AV REMEDIATION DATA
# ============================================================

df = pd.read_csv(AV_FILE)

df["event_time"] = pd.to_datetime(df["event_time"])

# ============================================================
# KEEP EVENTS WITH A REAL FILE PATH
# ============================================================

file_events = df[
    df["original_file"].notna() &
    (df["original_file"].astype(str).str.strip() != "")
].copy()

# ============================================================
# NORMALIZE FILE PATH
# ============================================================

file_events["original_file"] = (
    file_events["original_file"]
    .astype(str)
    .str.strip()
)

# ============================================================
# UNIQUE ENDPOINT + FILE COMBINATIONS
# ============================================================

unique_files = (
    file_events[
        [
            "endpoint_id",
            "original_file",
            "event_time",
            "action"
        ]
    ]
    .sort_values("event_time")
    .drop_duplicates(
        subset=["endpoint_id", "original_file"]
    )
)

# ============================================================
# SUMMARY
# ============================================================

summary = (
    file_events
    .groupby(["endpoint_id", "original_file"])
    .agg(
        av_events=("action", "size"),
        actions=("action", lambda x: ", ".join(sorted(set(x)))),
        first_seen=("event_time", "min"),
        last_seen=("event_time", "max")
    )
    .reset_index()
    .sort_values(
        ["endpoint_id", "first_seen"]
    )
)

print("=" * 90)
print("UNIQUE FILES ACTUALLY HANDLED BY AV")
print("=" * 90)

print(
    f"Unique endpoint/file combinations: {len(summary)}"
)

print()

for endpoint_id, group in summary.groupby("endpoint_id"):

    print("-" * 90)
    print(f"ENDPOINT: {endpoint_id}")

    for _, row in group.iterrows():

        print(
            f"  File: {row['original_file']}"
        )

        print(
            f"  AV events: {row['av_events']}"
        )

        print(
            f"  Actions: {row['actions']}"
        )

        print(
            f"  First seen: {row['first_seen']}"
        )

        print(
            f"  Last seen:  {row['last_seen']}"
        )

        print()

# ============================================================
# CLASSIFY BY PATH
# ============================================================

def classify_path(path):

    p = path.lower()

    if "/downloads/" in p:
        return "Downloads"

    if "/desktop/" in p:
        return "Desktop"

    if "/documents/" in p:
        return "Documents"

    if "/mail/" in p or "/evolution/" in p:
        return "Email/Mail"

    if "/.local/share/" in p:
        return "User Application Data"

    if "/tmp/" in p:
        return "Temporary Directory"

    if "/home/" in p:
        return "Home Directory"

    return "Other"


summary["location"] = summary["original_file"].apply(
    classify_path
)

print()
print("=" * 90)
print("AV FILE LOCATION SUMMARY")
print("=" * 90)

print(
    summary["location"]
    .value_counts()
    .to_string()
)

# ============================================================
# SAVE
# ============================================================

output_file = (
    BASE_DIR /
    "output" /
    "av_compromise_candidates.csv"
)

summary.to_csv(
    output_file,
    index=False
)

print()
print("=" * 90)
print("SAVED")
print("=" * 90)

print(output_file)