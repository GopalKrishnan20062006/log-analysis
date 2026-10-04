from pathlib import Path
import pandas as pd
import re


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
# LOAD SECURITY LOG
# ============================================================

print("=" * 70)
print("LOADING ENDPOINT SECURITY")
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


# ============================================================
# ONLY AV AND QUARANTINE EVENTS
# ============================================================

av = df[
    df["log_type"].isin(["av_scan", "quarantine"])
].copy()

print("AV + quarantine rows:", len(av))


# ============================================================
# 1. FIND ACTUAL AV DETECTION SIGNATURES
# ============================================================

print("\n" + "=" * 70)
print("ACTUAL AV DETECTION LINES")
print("=" * 70)

# According to the challenge format:
#
# Infected file is <path>: <Signature> FOUND

detection_pattern = re.compile(
    r"Infected file is (.+?):\s*(.+?)\s+FOUND",
    re.IGNORECASE
)

detections = []

for _, row in av.iterrows():

    message = str(row["message"])

    match = detection_pattern.search(message)

    if match:

        file_path = match.group(1).strip()
        signature = match.group(2).strip()

        detections.append({
            "endpoint_id": row["endpoint_id"],
            "endpoint_name": row["endpoint_name"],
            "unit": row["unit"],
            "event_time": row["event_time"],
            "file_path": file_path,
            "signature": signature,
            "message": message
        })


detections_df = pd.DataFrame(detections)

print("Actual AV detections found:", len(detections_df))

if len(detections_df) > 0:

    print("\nDetection records:")

    print(
        detections_df[
            [
                "endpoint_id",
                "endpoint_name",
                "unit",
                "event_time",
                "file_path",
                "signature"
            ]
        ].to_string(index=False)
    )

else:

    print("No AV detection lines matched the expected format.")


# ============================================================
# 2. QUARANTINED AND DELETED FILES
# ============================================================

print("\n" + "=" * 70)
print("QUARANTINED AND DELETED FILES")
print("=" * 70)

quarantine_pattern = re.compile(
    r"Quarantined and deleted:\s*(.+?)\s+to\s+(.+)",
    re.IGNORECASE
)

quarantined_files = []

for _, row in av.iterrows():

    message = str(row["message"])

    match = quarantine_pattern.search(message)

    if match:

        original_path = match.group(1).strip()
        quarantine_path = match.group(2).strip()

        quarantined_files.append({
            "endpoint_id": row["endpoint_id"],
            "endpoint_name": row["endpoint_name"],
            "unit": row["unit"],
            "event_time": row["event_time"],
            "original_path": original_path,
            "quarantine_path": quarantine_path
        })


quarantined_df = pd.DataFrame(quarantined_files)

print(
    "Quarantine actions found:",
    len(quarantined_df)
)

if len(quarantined_df) > 0:

    print(
        quarantined_df.to_string(index=False)
    )


# ============================================================
# 3. MALICIOUS FILES IN QUARANTINE INVENTORY
# ============================================================

print("\n" + "=" * 70)
print("MALICIOUS FILES IN QUARANTINE INVENTORY")
print("=" * 70)

malicious_pattern = re.compile(
    r"File:\s*(\S+).*?"
    r"FileType:\s*Malicious.*?"
    r"SHA256:\s*([a-fA-F0-9]{64})",
    re.IGNORECASE
)

malicious_files = []

for _, row in av.iterrows():

    message = str(row["message"])

    match = malicious_pattern.search(message)

    if match:

        quarantine_file = match.group(1)
        sha256 = match.group(2).lower()

        malicious_files.append({
            "endpoint_id": row["endpoint_id"],
            "endpoint_name": row["endpoint_name"],
            "unit": row["unit"],
            "event_time": row["event_time"],
            "quarantine_file": quarantine_file,
            "sha256": sha256
        })


malicious_df = pd.DataFrame(malicious_files)

print(
    "Malicious quarantine records:",
    len(malicious_df)
)

if len(malicious_df) > 0:

    print(
        malicious_df.to_string(index=False)
    )


# ============================================================
# 4. UNIQUE ENDPOINTS WITH REAL DETECTIONS
# ============================================================

print("\n" + "=" * 70)
print("ENDPOINTS WITH REAL AV DETECTIONS")
print("=" * 70)

if len(detections_df) > 0:

    endpoint_detection_summary = (
        detections_df
        .groupby(
            [
                "endpoint_id",
                "endpoint_name",
                "unit"
            ]
        )
        .agg(
            detection_count=("signature", "count"),
            signatures=("signature", lambda x: "; ".join(sorted(set(x))))
        )
        .reset_index()
        .sort_values(
            "detection_count",
            ascending=False
        )
    )

    print(
        endpoint_detection_summary.to_string(index=False)
    )

else:

    endpoint_detection_summary = pd.DataFrame()


# ============================================================
# 5. UNIQUE SIGNATURES
# ============================================================

print("\n" + "=" * 70)
print("UNIQUE DETECTION SIGNATURES")
print("=" * 70)

if len(detections_df) > 0:

    signature_counts = (
        detections_df["signature"]
        .value_counts()
    )

    print(signature_counts.to_string())

else:

    print("No signatures found.")


# ============================================================
# 6. SAVE RESULTS
# ============================================================

detections_df.to_csv(
    OUTPUT_DIR / "av_detections.csv",
    index=False
)

quarantined_df.to_csv(
    OUTPUT_DIR / "quarantine_actions.csv",
    index=False
)

malicious_df.to_csv(
    OUTPUT_DIR / "malicious_quarantine.csv",
    index=False
)

endpoint_detection_summary.to_csv(
    OUTPUT_DIR / "av_detection_summary.csv",
    index=False
)

print("\n" + "=" * 70)
print("FILES SAVED")
print("=" * 70)

print(OUTPUT_DIR / "av_detections.csv")
print(OUTPUT_DIR / "quarantine_actions.csv")
print(OUTPUT_DIR / "malicious_quarantine.csv")
print(OUTPUT_DIR / "av_detection_summary.csv")