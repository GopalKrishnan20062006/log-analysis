from pathlib import Path
import pandas as pd

# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output"

OUTPUT_DIR.mkdir(exist_ok=True)

SECURITY_FILE = DATA_DIR / "endpoint_security.csv"

DATETIME_FORMAT = "%d-%m-%Y %H:%M:%S"


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 70)
print("LOADING ENDPOINT SECURITY LOG")
print("=" * 70)

df = pd.read_csv(SECURITY_FILE)

df["event_time"] = pd.to_datetime(
    df["event_time"],
    format=DATETIME_FORMAT,
    errors="coerce"
)

df["received_time"] = pd.to_datetime(
    df["received_time"],
    format=DATETIME_FORMAT,
    errors="coerce"
)

print("Total rows:", len(df))


# ============================================================
# 1. LOG TYPE DISTRIBUTION
# ============================================================

print("\n" + "=" * 70)
print("LOG TYPE DISTRIBUTION")
print("=" * 70)

print(
    df["log_type"]
    .value_counts()
)


# ============================================================
# 2. BASIC INFORMATION FOR EACH LOG TYPE
# ============================================================

print("\n" + "=" * 70)
print("EVENT COUNTS BY ENDPOINT")
print("=" * 70)

endpoint_counts = (
    df.groupby(
        ["endpoint_id", "endpoint_name", "unit", "log_type"]
    )
    .size()
    .reset_index(name="event_count")
    .sort_values(
        "event_count",
        ascending=False
    )
)

print(endpoint_counts.to_string(index=False))


# ============================================================
# 3. QUARANTINE ANALYSIS
# ============================================================

print("\n" + "=" * 70)
print("QUARANTINE ANALYSIS")
print("=" * 70)

quarantine = df[
    df["log_type"] == "quarantine"
].copy()

print("Total quarantine rows:", len(quarantine))

print("\nQuarantine rows by endpoint:")

quarantine_by_endpoint = (
    quarantine
    .groupby(
        ["endpoint_id", "endpoint_name", "unit"]
    )
    .size()
    .reset_index(name="quarantine_events")
    .sort_values(
        "quarantine_events",
        ascending=False
    )
)

print(
    quarantine_by_endpoint.to_string(index=False)
)


# ============================================================
# 4. DISPLAY QUARANTINE MESSAGE EXAMPLES
# ============================================================

print("\n" + "=" * 70)
print("QUARANTINE MESSAGE EXAMPLES")
print("=" * 70)

for _, row in quarantine.head(30).iterrows():

    print(
        f"\n[{row['event_time']}] "
        f"{row['endpoint_id']} "
        f"({row['endpoint_name']})"
    )

    print(row["message"])


# ============================================================
# 5. AV SCAN ANALYSIS
# ============================================================

print("\n" + "=" * 70)
print("AV SCAN ANALYSIS")
print("=" * 70)

av = df[
    df["log_type"] == "av_scan"
].copy()

print("Total AV scan rows:", len(av))

print("\nAV scan rows by endpoint:")

av_by_endpoint = (
    av
    .groupby(
        ["endpoint_id", "endpoint_name", "unit"]
    )
    .size()
    .reset_index(name="av_events")
    .sort_values(
        "av_events",
        ascending=False
    )
)

print(
    av_by_endpoint.to_string(index=False)
)


# ============================================================
# 6. DISPLAY AV SCAN MESSAGE EXAMPLES
# ============================================================

print("\n" + "=" * 70)
print("AV SCAN MESSAGE EXAMPLES")
print("=" * 70)

for _, row in av.head(50).iterrows():

    print(
        f"\n[{row['event_time']}] "
        f"{row['endpoint_id']} "
        f"({row['endpoint_name']})"
    )

    print(row["message"])


# ============================================================
# 7. WEB BLOCK ANALYSIS
# ============================================================

print("\n" + "=" * 70)
print("WEB BLOCK ANALYSIS")
print("=" * 70)

web_block = df[
    df["log_type"] == "web_block"
].copy()

print("Total web-block rows:", len(web_block))

print("\nWeb blocks by endpoint:")

blocks_by_endpoint = (
    web_block
    .groupby(
        ["endpoint_id", "endpoint_name", "unit"]
    )
    .size()
    .reset_index(name="blocked_events")
    .sort_values(
        "blocked_events",
        ascending=False
    )
)

print(
    blocks_by_endpoint.to_string(index=False)
)


# ============================================================
# 8. DISPLAY WEB-BLOCK MESSAGE EXAMPLES
# ============================================================

print("\n" + "=" * 70)
print("WEB-BLOCK MESSAGE EXAMPLES")
print("=" * 70)

for _, row in web_block.head(50).iterrows():

    print(
        f"\n[{row['event_time']}] "
        f"{row['endpoint_id']} "
        f"({row['endpoint_name']})"
    )

    print(row["message"])


# ============================================================
# 9. SAVE SUMMARY TABLES
# ============================================================

endpoint_counts.to_csv(
    OUTPUT_DIR / "security_events_by_endpoint.csv",
    index=False
)

quarantine_by_endpoint.to_csv(
    OUTPUT_DIR / "quarantine_by_endpoint.csv",
    index=False
)

av_by_endpoint.to_csv(
    OUTPUT_DIR / "av_events_by_endpoint.csv",
    index=False
)

blocks_by_endpoint.to_csv(
    OUTPUT_DIR / "web_blocks_by_endpoint.csv",
    index=False
)

print("\n" + "=" * 70)
print("SUMMARY FILES SAVED")
print("=" * 70)

print(
    OUTPUT_DIR / "security_events_by_endpoint.csv"
)

print(
    OUTPUT_DIR / "quarantine_by_endpoint.csv"
)

print(
    OUTPUT_DIR / "av_events_by_endpoint.csv"
)

print(
    OUTPUT_DIR / "web_blocks_by_endpoint.csv"
)