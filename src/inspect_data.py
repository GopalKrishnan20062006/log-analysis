from pathlib import Path
import pandas as pd


# --------------------------------------------------
# Paths
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


FILES = {
    "web_activity": DATA_DIR / "web_activity.csv",
    "endpoint_security": DATA_DIR / "endpoint_security.csv",
    "usb_events": DATA_DIR / "usb_events.csv",
}


# --------------------------------------------------
# Inspect each dataset
# --------------------------------------------------

for name, path in FILES.items():

    print("\n" + "=" * 70)
    print(f"DATASET: {name}")
    print("=" * 70)

    print(f"File: {path}")

    if not path.exists():
        print("ERROR: File does not exist!")
        continue

    print(f"Size: {path.stat().st_size / (1024 ** 2):.2f} MB")

    # Only read a small sample first
    df = pd.read_csv(path, nrows=5)

    print("\nColumns:")
    for column in df.columns:
        print(f"  - {column}")

    print("\nNumber of columns:")
    print(len(df.columns))

    print("\nSample rows:")
    print(df.to_string(index=False))

    print("\nData types:")
    print(df.dtypes)

    print("\nMissing values in sample:")
    print(df.isna().sum())

    # --------------------------------------------------
# Inspect log types
# --------------------------------------------------

print("\n" + "=" * 70)
print("LOG TYPE ANALYSIS")
print("=" * 70)

for name, path in FILES.items():

    print(f"\n{name.upper()}")

    # Read only the columns needed for this check
    df = pd.read_csv(
        path,
        usecols=["log_type"]
    )

    print(df["log_type"].value_counts(dropna=False))

    # --------------------------------------------------
# Endpoint inventory
# --------------------------------------------------

print("\n" + "=" * 70)
print("ENDPOINT INVENTORY")
print("=" * 70)

for name, path in FILES.items():

    print(f"\n{name.upper()}")

    df = pd.read_csv(
        path,
        usecols=[
            "endpoint_id",
            "endpoint_name",
            "mac",
            "unit"
        ]
    )

    print("Unique endpoint IDs:", df["endpoint_id"].nunique())
    print("Unique endpoint names:", df["endpoint_name"].nunique())
    print("Unique MAC addresses:", df["mac"].nunique())
    print("Unique units:", df["unit"].nunique())