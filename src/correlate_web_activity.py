from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output"

DATETIME_FORMAT = "%d-%m-%Y %H:%M:%S"

print("=" * 70)
print("STEP 7 - EXTRACTING SUSPICIOUS WEB ACTIVITY")
print("=" * 70)

# ---------------------------------------------------------
# 1. Load malicious quarantine events
# ---------------------------------------------------------

malicious_file = OUTPUT_DIR / "malicious_quarantine_detailed.csv"

malicious = pd.read_csv(malicious_file)

malicious["event_time"] = pd.to_datetime(
    malicious["event_time"],
    errors="coerce"
)

# First malicious event for each endpoint
first_events = (
    malicious
    .groupby("endpoint_id")
    .agg(
        first_malicious_time=("event_time", "min"),
        endpoint_name=("endpoint_name", "first"),
        unit=("unit", "first")
    )
    .reset_index()
)

print(f"Affected endpoints: {len(first_events)}")

# ---------------------------------------------------------
# 2. Load web activity
# ---------------------------------------------------------

print("\nLoading web activity...")

web = pd.read_csv(
    DATA_DIR / "web_activity.csv"
)

web["event_time"] = pd.to_datetime(
    web["event_time"],
    format=DATETIME_FORMAT,
    errors="coerce"
)

print(f"Web activity rows: {len(web)}")

# ---------------------------------------------------------
# 3. Merge with affected endpoints
# ---------------------------------------------------------

merged = web.merge(
    first_events,
    on="endpoint_id",
    how="inner"
)

# Calculate time difference from first malicious event
merged["time_difference_hours"] = (
    merged["event_time"]
    - merged["first_malicious_time"]
).dt.total_seconds() / 3600

# Only look 24 hours before to 24 hours after
window = merged[
    merged["time_difference_hours"].between(-24, 24)
].copy()

print(
    f"Web events within +/-24 hours: {len(window)}"
)

# ---------------------------------------------------------
# 4. Extract destination from message
# ---------------------------------------------------------

def extract_destination(message):
    if pd.isna(message):
        return ""

    message = str(message).strip()

    return message


window["destination"] = window["message"].apply(
    extract_destination
)

# ---------------------------------------------------------
# 5. Remove obvious normal infrastructure
# ---------------------------------------------------------

normal_patterns = [
    "google.com",
    "google.co.in",
    "google-analytics.com",
    "googletagmanager.com",
    "gstatic.com",
    "googleapis.com",
    "mozilla.org",
    "mozilla.com",
    "mozilla.net",
    "fastly.net",
    "fastly-edge.com",
    "cloudfront.net",
    "awsdns-",
    "icann.org",
    "example.org",
    "lan-",
    ".local",
    ".bbrouter",
    ".hgu_lan",
    ".dlink"
]

def looks_normal(destination):

    destination = destination.lower()

    for pattern in normal_patterns:
        if pattern in destination:
            return True

    return False


window["normal_destination"] = window[
    "destination"
].apply(looks_normal)

suspicious = window[
    ~window["normal_destination"]
].copy()

# ---------------------------------------------------------
# 6. Sort by endpoint and time
# ---------------------------------------------------------

suspicious = suspicious.sort_values(
    ["endpoint_id", "event_time"]
)

# ---------------------------------------------------------
# 7. Save suspicious activity
# ---------------------------------------------------------

output_file = (
    OUTPUT_DIR /
    "suspicious_web_activity.csv"
)

suspicious.to_csv(
    output_file,
    index=False
)

# ---------------------------------------------------------
# 8. Print concise results
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("SUSPICIOUS WEB ACTIVITY")
print("=" * 70)

print(
    f"Potentially interesting web events: "
    f"{len(suspicious)}"
)

# Show only the first 10 suspicious events per endpoint
for endpoint_id in first_events["endpoint_id"]:

    rows = suspicious[
        suspicious["endpoint_id"] == endpoint_id
    ]

    if len(rows) == 0:
        continue

    info = first_events[
        first_events["endpoint_id"] == endpoint_id
    ].iloc[0]

    print("\n" + "-" * 70)

    print(
        f"Endpoint: {endpoint_id} | "
        f"{info['endpoint_name']} | "
        f"{info['unit']}"
    )

    print(
        f"First malicious event: "
        f"{info['first_malicious_time']}"
    )

    print(
        f"Suspicious web events: {len(rows)}"
    )

    print(
        rows[
            [
                "event_time",
                "destination",
                "time_difference_hours"
            ]
        ]
        .head(10)
        .to_string(index=False)
    )

print("\n" + "=" * 70)
print("SAVED")
print("=" * 70)

print(output_file)