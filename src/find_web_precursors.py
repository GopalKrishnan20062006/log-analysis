from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"

INPUT_FILE = OUTPUT_DIR / "malicious_web_correlation_24h.csv"
OUTPUT_FILE = OUTPUT_DIR / "web_precursors.csv"

print("=" * 70)
print("STEP 8 - WEB PRECURSOR ANALYSIS")
print("=" * 70)

# ---------------------------------------------------------
# 1. Load existing correlation data
# ---------------------------------------------------------

df = pd.read_csv(INPUT_FILE)

df["event_time"] = pd.to_datetime(
    df["event_time"],
    errors="coerce"
)

df["first_malicious_time"] = pd.to_datetime(
    df["first_malicious_time"],
    errors="coerce"
)

print(f"Correlation rows loaded: {len(df):,}")

# ---------------------------------------------------------
# 2. Keep only web activity BEFORE detection
#    within the previous 2 hours
# ---------------------------------------------------------

precursors = df[
    (df["time_difference_hours"] < 0) &
    (df["time_difference_hours"] >= -2)
].copy()

print(
    f"Web events in the 2 hours before detection: "
    f"{len(precursors):,}"
)

# ---------------------------------------------------------
# 3. Extract destination
# ---------------------------------------------------------

precursors["destination"] = (
    precursors["message"]
    .astype(str)
    .str.strip()
)

# ---------------------------------------------------------
# 4. Group by endpoint and destination
# ---------------------------------------------------------

summary = (
    precursors
    .groupby(
        ["endpoint_id", "destination"],
        as_index=False
    )
    .agg(
        web_events=("destination", "size"),
        first_seen=("event_time", "min"),
        last_seen=("event_time", "max"),
        closest_to_detection_hours=(
            "time_difference_hours",
            "max"
        )
    )
)

# ---------------------------------------------------------
# 5. Sort
# ---------------------------------------------------------

summary = summary.sort_values(
    ["endpoint_id", "web_events"],
    ascending=[True, False]
)

# ---------------------------------------------------------
# 6. Save complete results
# ---------------------------------------------------------

summary.to_csv(
    OUTPUT_FILE,
    index=False
)

# ---------------------------------------------------------
# 7. Print concise results
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("TOP WEB PRECURSORS")
print("=" * 70)

for endpoint_id, group in summary.groupby(
    "endpoint_id",
    sort=False
):

    print("\n" + "-" * 70)
    print(f"Endpoint: {endpoint_id}")

    print(
        group[
            [
                "destination",
                "web_events",
                "closest_to_detection_hours"
            ]
        ]
        .head(10)
        .to_string(index=False)
    )

print("\n" + "=" * 70)
print("SAVED")
print("=" * 70)

print(OUTPUT_FILE)