import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

AV_FILE = BASE_DIR / "output" / "av_remediation_events.csv"
WEB_FILE = BASE_DIR / "data" / "web_activity.csv"

# ============================================================
# LOAD DATA
# ============================================================

av = pd.read_csv(AV_FILE)
web = pd.read_csv(WEB_FILE)

av["event_time"] = pd.to_datetime(
    av["event_time"],
    format="%Y-%m-%d %H:%M:%S"
)

web["event_time"] = pd.to_datetime(
    web["event_time"],
    format="%d-%m-%Y %H:%M:%S"
)

# ============================================================
# ONLY REAL AV REMEDIATION EVENTS
# ============================================================

av_actions = av[
    av["action"] == "quarantined_deleted"
].copy()

av_actions = av_actions[
    av_actions["original_file"].notna()
].copy()

print("=" * 100)
print("AV DETECTION -> PRECEDING WEB ACTIVITY")
print("=" * 100)

results = []

# ============================================================
# CORRELATE EACH AV DETECTION WITH PREVIOUS 6 HOURS
# ============================================================

for _, av_row in av_actions.iterrows():

    endpoint = av_row["endpoint_id"]
    av_time = av_row["event_time"]
    original_file = av_row["original_file"]

    start_time = av_time - pd.Timedelta(hours=24)

    events = web[
        (web["endpoint_id"] == endpoint) &
        (web["event_time"] >= start_time) &
        (web["event_time"] <= av_time)
    ].copy()

    if events.empty:
        continue

    events["minutes_before_av"] = (
        (av_time - events["event_time"])
        .dt.total_seconds() / 60
    )

    for _, event in events.iterrows():

        results.append({
            "endpoint_id": endpoint,
            "av_time": av_time,
            "original_file": original_file,
            "web_time": event["event_time"],
            "minutes_before_av": event["minutes_before_av"],
            "destination": event["message"],
            "unit": event["unit"]
        })

# ============================================================
# SAVE
# ============================================================

result = pd.DataFrame(results)

output_file = BASE_DIR / "output" / "av_web_correlation_6h.csv"

result.to_csv(output_file, index=False)

# ============================================================
# PRINT ONLY THE MOST RELEVANT EVENTS
# ============================================================

print(f"\nTotal correlated web events: {len(result)}")

if not result.empty:

    # Show events closest to the AV detection
    closest = (
        result
        .sort_values(
            ["endpoint_id", "av_time", "minutes_before_av"]
        )
        .groupby(
            ["endpoint_id", "av_time", "original_file"],
            as_index=False
        )
        .head(15)
    )

    for (
        endpoint,
        av_time,
        original_file
    ), group in closest.groupby(
        ["endpoint_id", "av_time", "original_file"]
    ):

        print("\n" + "-" * 100)
        print(f"ENDPOINT: {endpoint}")
        print(f"AV TIME:  {av_time}")
        print(f"FILE:     {original_file}")

        for _, row in group.iterrows():

            print(
                f"  {row['web_time']} "
                f"({row['minutes_before_av']:.2f} min before) "
                f"-> {row['destination']}"
            )

print("\n" + "=" * 100)
print("SAVED")
print("=" * 100)
print(output_file)