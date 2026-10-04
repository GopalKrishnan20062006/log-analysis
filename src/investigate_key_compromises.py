from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output"

AV_FILE = OUTPUT_DIR / "av_compromise_candidates.csv"
WEB_FILE = DATA_DIR / "web_activity.csv"

print("Loading data...")

av = pd.read_csv(AV_FILE)
web = pd.read_csv(WEB_FILE)

print("\nAV columns:")
print(av.columns.tolist())

print("\nWeb columns:")
print(web.columns.tolist())

# ---------------------------------------------------------
# Find the timestamp column in AV data
# ---------------------------------------------------------

possible_av_time_columns = [
    "first_seen"
]
av_time_column = None

for column in possible_av_time_columns:
    if column in av.columns:
        av_time_column = column
        break

if av_time_column is None:
    raise ValueError(
        "Could not find an AV timestamp column. "
        f"Available columns: {av.columns.tolist()}"
    )

print(f"\nUsing AV timestamp column: {av_time_column}")

av["av_time"] = pd.to_datetime(
    av[av_time_column],
    errors="coerce"
)

web["event_time"] = pd.to_datetime(
    web["event_time"],
    format="%d-%m-%Y %H:%M:%S",
    errors="coerce"
)

# ---------------------------------------------------------
# Key compromise cases
# ---------------------------------------------------------

key_endpoints = {
    "EPGSQVEB",
    "EPQKOBYG",
    "EPSES7ZK",
    "EPVSWBNA",
    "EPLFOXSS"
}

av = av[
    av["endpoint_id"].isin(key_endpoints)
].copy()

print(f"\nKey AV records found: {len(av)}")

# ---------------------------------------------------------
# Background destinations to ignore
# ---------------------------------------------------------

background_destinations = {
    "8.8.8.8",
    "8.8.4.4",
    "dns.google",
    "google.com",
    "www.google.com",
    "142.251.222.206",
    "142.251.42.206",
    "142.250.195.14",
    "localhost"
}

# ---------------------------------------------------------
# Correlate web activity around AV remediation
# ---------------------------------------------------------

results = []

for _, av_row in av.iterrows():

    endpoint = av_row["endpoint_id"]
    av_time = av_row["av_time"]

    if pd.isna(av_time):
        continue

    start_time = av_time - pd.Timedelta(hours=24)
    end_time = av_time + pd.Timedelta(hours=6)

    endpoint_web = web[
        (web["endpoint_id"] == endpoint) &
        (web["event_time"] >= start_time) &
        (web["event_time"] <= end_time)
    ].copy()

    endpoint_web = endpoint_web[
        ~endpoint_web["message"].astype(str).isin(
            background_destinations
        )
    ]

    for _, web_row in endpoint_web.iterrows():

        results.append({
            "endpoint_id": endpoint,
            "av_time": av_time,
            "infected_file": av_row.get("infected_file", ""),
            "web_time": web_row["event_time"],
            "destination": web_row["message"],
            "hours_from_av": (
                web_row["event_time"] - av_time
            ).total_seconds() / 3600
        })

# ---------------------------------------------------------
# Save results
# ---------------------------------------------------------

result_df = pd.DataFrame(results)

output_file = OUTPUT_DIR / "key_compromise_web_activity.csv"

result_df.to_csv(
    output_file,
    index=False
)

print("\n" + "=" * 60)
print("KEY COMPROMISE WEB INVESTIGATION")
print("=" * 60)

print(f"\nResults found: {len(result_df)}")
print(f"Saved to: {output_file}")

if not result_df.empty:

    for endpoint in key_endpoints:

        subset = result_df[
            result_df["endpoint_id"] == endpoint
        ]

        print(f"\n{endpoint}: {len(subset)} unusual web events")

        if not subset.empty:
            print(
                subset[
                    [
                        "web_time",
                        "destination",
                        "hours_from_av"
                    ]
                ].head(20).to_string(index=False)
            )