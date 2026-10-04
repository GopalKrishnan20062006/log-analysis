from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output"

DATETIME_FORMAT = "%d-%m-%Y %H:%M:%S"

print("=" * 70)
print("STEP 10 - INFECTION TIMELINE")
print("=" * 70)

# ---------------------------------------------------------
# 1. Load malicious quarantine records
# ---------------------------------------------------------

malicious = pd.read_csv(
    OUTPUT_DIR / "malicious_quarantine_detailed.csv"
)

malicious["event_time"] = pd.to_datetime(
    malicious["event_time"],
    errors="coerce"
)

print(
    f"Malicious quarantine records: "
    f"{len(malicious)}"
)

# ---------------------------------------------------------
# 2. Load USB events
# ---------------------------------------------------------

usb = pd.read_csv(
    DATA_DIR / "usb_events.csv"
)

usb["event_time"] = pd.to_datetime(
    usb["event_time"],
    format=DATETIME_FORMAT,
    errors="coerce"
)

print(
    f"USB events: {len(usb)}"
)

# ---------------------------------------------------------
# 3. Load web blocks
# ---------------------------------------------------------

security = pd.read_csv(
    DATA_DIR / "endpoint_security.csv"
)

security["event_time"] = pd.to_datetime(
    security["event_time"],
    format=DATETIME_FORMAT,
    errors="coerce"
)

web_blocks = security[
    security["log_type"].astype(str).str.lower()
    == "web_block"
].copy()

print(
    f"Web-block events: {len(web_blocks)}"
)

# ---------------------------------------------------------
# 4. Create timeline
# ---------------------------------------------------------

timeline = []

for _, malicious_row in malicious.iterrows():

    endpoint = malicious_row["endpoint_id"]
    detection_time = malicious_row["event_time"]

    # ---------------------------------------------
    # USB events within 24h BEFORE detection
    # ---------------------------------------------

    endpoint_usb = usb[
        (usb["endpoint_id"] == endpoint) &
        (usb["event_time"] <= detection_time) &
        (
            usb["event_time"]
            >= detection_time - pd.Timedelta(hours=24)
        )
    ].copy()

    # ---------------------------------------------
    # Web blocks within 24h BEFORE detection
    # ---------------------------------------------

    endpoint_blocks = web_blocks[
        (web_blocks["endpoint_id"] == endpoint) &
        (web_blocks["event_time"] <= detection_time) &
        (
            web_blocks["event_time"]
            >= detection_time - pd.Timedelta(hours=24)
        )
    ].copy()

    # ---------------------------------------------
    # Create one timeline row
    # ---------------------------------------------

    usb_events = []

    for _, row in endpoint_usb.iterrows():

        usb_events.append(
            f"{row['event_time']} | {row['message']}"
        )

    blocked_events = []

    for _, row in endpoint_blocks.iterrows():

        blocked_events.append(
            f"{row['event_time']} | {row['message']}"
        )

    timeline.append(
        {
            "endpoint_id": endpoint,
            "endpoint_name": malicious_row[
                "endpoint_name"
            ],
            "unit": malicious_row["unit"],
            "malicious_event_time": detection_time,
            "quarantine_file": malicious_row[
                "quarantine_file"
            ],
            "sha256": malicious_row["sha256"],
            "usb_events_before_detection": " || ".join(
                usb_events
            ),
            "web_blocks_before_detection": " || ".join(
                blocked_events
            ),
            "usb_event_count": len(endpoint_usb),
            "web_block_count": len(endpoint_blocks)
        }
    )

# ---------------------------------------------------------
# 5. Convert to dataframe
# ---------------------------------------------------------

timeline_df = pd.DataFrame(timeline)

# ---------------------------------------------------------
# 6. Save
# ---------------------------------------------------------

OUTPUT_FILE = (
    OUTPUT_DIR /
    "infection_timeline.csv"
)

timeline_df.to_csv(
    OUTPUT_FILE,
    index=False
)

# ---------------------------------------------------------
# 7. Print useful cases
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("ENDPOINTS WITH USB ACTIVITY BEFORE DETECTION")
print("=" * 70)

usb_cases = timeline_df[
    timeline_df["usb_event_count"] > 0
]

if len(usb_cases) == 0:

    print("No affected endpoint had USB activity in the previous 24 hours.")

else:

    for endpoint_id, group in usb_cases.groupby(
        "endpoint_id"
    ):

        print("\n" + "-" * 70)
        print(f"Endpoint: {endpoint_id}")

        print(
            group[
                [
                    "malicious_event_time",
                    "quarantine_file",
                    "usb_event_count",
                    "usb_events_before_detection"
                ]
            ].to_string(index=False)
        )

print("\n" + "=" * 70)
print("ENDPOINTS WITH WEB BLOCKS BEFORE DETECTION")
print("=" * 70)

block_cases = timeline_df[
    timeline_df["web_block_count"] > 0
]

if len(block_cases) == 0:

    print("No affected endpoint had web blocks in the previous 24 hours.")

else:

    for endpoint_id, group in block_cases.groupby(
        "endpoint_id"
    ):

        print("\n" + "-" * 70)
        print(f"Endpoint: {endpoint_id}")

        print(
            group[
                [
                    "malicious_event_time",
                    "quarantine_file",
                    "web_block_count",
                    "web_blocks_before_detection"
                ]
            ].to_string(index=False)
        )

print("\n" + "=" * 70)
print("SAVED")
print("=" * 70)

print(OUTPUT_FILE)