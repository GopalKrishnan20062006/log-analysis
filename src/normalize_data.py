from pathlib import Path
import pandas as pd

# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output"

OUTPUT_DIR.mkdir(exist_ok=True)

# ============================================================
# FILE PATHS
# ============================================================

WEB_FILE = DATA_DIR / "web_activity.csv"
SECURITY_FILE = DATA_DIR / "endpoint_security.csv"
USB_FILE = DATA_DIR / "usb_events.csv"

# ============================================================
# COMMON DATETIME FORMAT
# ============================================================

DATETIME_FORMAT = "%d-%m-%Y %H:%M:%S"


# ============================================================
# 1. LOAD WEB ACTIVITY
# ============================================================

print("=" * 70)
print("LOADING WEB ACTIVITY")
print("=" * 70)

web = pd.read_csv(WEB_FILE)

print("Rows:", len(web))
print("Columns:", len(web.columns))

# Convert timestamps
web["event_time"] = pd.to_datetime(
    web["event_time"],
    format=DATETIME_FORMAT,
    errors="coerce"
)

web["received_time"] = pd.to_datetime(
    web["received_time"],
    format=DATETIME_FORMAT,
    errors="coerce"
)

print("\nInvalid event_time values:",
      web["event_time"].isna().sum())

print("Invalid received_time values:",
      web["received_time"].isna().sum())


# ============================================================
# 2. LOAD ENDPOINT SECURITY
# ============================================================

print("\n" + "=" * 70)
print("LOADING ENDPOINT SECURITY")
print("=" * 70)

security = pd.read_csv(SECURITY_FILE)

print("Rows:", len(security))
print("Columns:", len(security.columns))

security["event_time"] = pd.to_datetime(
    security["event_time"],
    format=DATETIME_FORMAT,
    errors="coerce"
)

security["received_time"] = pd.to_datetime(
    security["received_time"],
    format=DATETIME_FORMAT,
    errors="coerce"
)

print("\nInvalid event_time values:",
      security["event_time"].isna().sum())

print("Invalid received_time values:",
      security["received_time"].isna().sum())


# ============================================================
# 3. LOAD USB EVENTS
# ============================================================

print("\n" + "=" * 70)
print("LOADING USB EVENTS")
print("=" * 70)

usb = pd.read_csv(USB_FILE)

print("Rows:", len(usb))
print("Columns:", len(usb.columns))

usb["event_time"] = pd.to_datetime(
    usb["event_time"],
    format=DATETIME_FORMAT,
    errors="coerce"
)

usb["received_time"] = pd.to_datetime(
    usb["received_time"],
    format=DATETIME_FORMAT,
    errors="coerce"
)

print("\nInvalid event_time values:",
      usb["event_time"].isna().sum())

print("Invalid received_time values:",
      usb["received_time"].isna().sum())


# ============================================================
# 4. CREATE MASTER ENDPOINT INVENTORY
# ============================================================

print("\n" + "=" * 70)
print("CREATING MASTER ENDPOINT INVENTORY")
print("=" * 70)

inventory_columns = [
    "endpoint_id",
    "endpoint_name",
    "mac",
    "unit"
]

web_inventory = web[inventory_columns].drop_duplicates()
security_inventory = security[inventory_columns].drop_duplicates()
usb_inventory = usb[inventory_columns].drop_duplicates()

inventory = pd.concat(
    [
        web_inventory,
        security_inventory,
        usb_inventory
    ],
    ignore_index=True
)

inventory = inventory.drop_duplicates(
    subset=["endpoint_id"]
)

inventory = inventory.sort_values(
    by="endpoint_id"
).reset_index(drop=True)

print("Total unique endpoints:", len(inventory))

print("\nEndpoints per unit:")
print(
    inventory["unit"]
    .value_counts()
    .sort_index()
)


# ============================================================
# 5. CHECK FOR INCONSISTENT ENDPOINT DETAILS
# ============================================================

print("\n" + "=" * 70)
print("CHECKING ENDPOINT CONSISTENCY")
print("=" * 70)

# Group by endpoint ID and see whether an endpoint
# appears with multiple names, MACs, or units.

endpoint_consistency = pd.concat(
    [
        web[inventory_columns],
        security[inventory_columns],
        usb[inventory_columns]
    ],
    ignore_index=True
)

for column in ["endpoint_name", "mac", "unit"]:

    counts = (
        endpoint_consistency
        .groupby("endpoint_id")[column]
        .nunique()
    )

    inconsistent = counts[counts > 1]

    print(
        f"\n{column}: "
        f"{len(inconsistent)} endpoints have multiple values"
    )

    if len(inconsistent) > 0:
        print(inconsistent)


# ============================================================
# 6. CHECK WHICH ENDPOINTS ARE MISSING FROM SECURITY LOGS
# ============================================================

print("\n" + "=" * 70)
print("ENDPOINT COVERAGE")
print("=" * 70)

web_endpoints = set(web["endpoint_id"].dropna())
security_endpoints = set(security["endpoint_id"].dropna())
usb_endpoints = set(usb["endpoint_id"].dropna())

missing_security = sorted(
    web_endpoints - security_endpoints
)

print(
    "Endpoints in web activity but not in "
    f"endpoint security: {len(missing_security)}"
)

if missing_security:
    print("\nMissing endpoint IDs:")
    for endpoint in missing_security:
        print(" ", endpoint)


# ============================================================
# 7. TIMESTAMP RANGE
# ============================================================

print("\n" + "=" * 70)
print("TIMESTAMP RANGES")
print("=" * 70)

datasets = {
    "WEB_ACTIVITY": web,
    "ENDPOINT_SECURITY": security,
    "USB_EVENTS": usb
}

for name, df in datasets.items():

    print(f"\n{name}")

    print(
        "Event time:",
        df["event_time"].min(),
        "to",
        df["event_time"].max()
    )

    print(
        "Received time:",
        df["received_time"].min(),
        "to",
        df["received_time"].max()
    )


# ============================================================
# 8. SAVE MASTER INVENTORY
# ============================================================

inventory_file = OUTPUT_DIR / "endpoint_inventory.csv"

inventory.to_csv(
    inventory_file,
    index=False
)

print("\n" + "=" * 70)
print("DONE")
print("=" * 70)

print("Saved:", inventory_file)