from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output"

DATETIME_FORMAT = "%d-%m-%Y %H:%M:%S"

print("=" * 70)
print("STEP 9 - WEB BLOCK CORRELATION")
print("=" * 70)

# ---------------------------------------------------------
# 1. Load malicious endpoints
# ---------------------------------------------------------

malicious = pd.read_csv(
    OUTPUT_DIR / "malicious_quarantine_detailed.csv"
)

malicious["event_time"] = pd.to_datetime(
    malicious["event_time"],
    errors="coerce"
)

# First malicious event per endpoint
first_events = (
    malicious
    .groupby("endpoint_id")
    .agg(
        first_malicious_time=("event_time", "min")
    )
    .reset_index()
)

affected_endpoints = set(
    first_events["endpoint_id"]
)

print(
    f"Endpoints with malicious quarantine records: "
    f"{len(affected_endpoints)}"
)

# ---------------------------------------------------------
# 2. Load endpoint security log
# ---------------------------------------------------------

print("\nLoading endpoint security logs...")

security = pd.read_csv(
    DATA_DIR / "endpoint_security.csv"
)

security["event_time"] = pd.to_datetime(
    security["event_time"],
    format=DATETIME_FORMAT,
    errors="coerce"
)

# ---------------------------------------------------------
# 3. Extract web-block events
# ---------------------------------------------------------

web_blocks = security[
    security["log_type"].astype(str).str.lower()
    == "web_block"
].copy()

print(
    f"Total web-block events: "
    f"{len(web_blocks):,}"
)

# Only affected endpoints
web_blocks = web_blocks[
    web_blocks["endpoint_id"].isin(affected_endpoints)
].copy()

print(
    f"Web-block events on affected endpoints: "
    f"{len(web_blocks):,}"
)

# ---------------------------------------------------------
# 4. Add first malicious time
# ---------------------------------------------------------

web_blocks = web_blocks.merge(
    first_events,
    on="endpoint_id",
    how="left"
)

web_blocks["time_difference_hours"] = (
    web_blocks["event_time"]
    - web_blocks["first_malicious_time"]
).dt.total_seconds() / 3600

# ---------------------------------------------------------
# 5. Focus on blocks around compromise
# ---------------------------------------------------------

around_compromise = web_blocks[
    web_blocks["time_difference_hours"].between(-24, 24)
].copy()

# ---------------------------------------------------------
# 6. Save complete result
# ---------------------------------------------------------

OUTPUT_FILE = (
    OUTPUT_DIR /
    "affected_endpoint_web_blocks.csv"
)

around_compromise = around_compromise.sort_values(
    ["endpoint_id", "event_time"]
)

around_compromise.to_csv(
    OUTPUT_FILE,
    index=False
)

# ---------------------------------------------------------
# 7. Print results
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("WEB BLOCKS AROUND MALICIOUS EVENTS")
print("=" * 70)

if len(around_compromise) == 0:

    print(
        "No web-block events found within "
        "+/-24 hours of malicious detection."
    )

else:

    print(
        f"Web blocks within +/-24 hours: "
        f"{len(around_compromise):,}"
    )

    for endpoint_id, group in around_compromise.groupby(
        "endpoint_id",
        sort=False
    ):

        first = group.iloc[0]

        print("\n" + "-" * 70)

        print(
            f"Endpoint: {endpoint_id}"
        )

        print(
            f"First malicious event: "
            f"{first['first_malicious_time']}"
        )

        print(
            f"Web blocks: {len(group)}"
        )

        print(
            group[
                [
                    "event_time",
                    "message",
                    "time_difference_hours"
                ]
            ]
            .to_string(index=False)
        )

print("\n" + "=" * 70)
print("SAVED")
print("=" * 70)

print(OUTPUT_FILE)