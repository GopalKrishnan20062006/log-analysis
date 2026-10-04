import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"

# Load confirmed AV remediation data
av = pd.read_csv(OUTPUT_DIR / "av_compromise_candidates.csv")

# Endpoint classifications based on the investigation performed so far
classification = {
    # Strong endpoint-specific malicious artifacts
    "EPGSQVEB": {
        "status": "CONFIRMED",
        "reason": "AV quarantined and deleted Final_Documents.zip; unique malicious SHA256; two local copies"
    },

    "EPQKOBYG": {
        "status": "CONFIRMED",
        "reason": "AV quarantined and deleted malicious printer-related executable from Downloads; unique SHA256"
    },

    "EPSES7ZK": {
        "status": "CONFIRMED",
        "reason": "AV quarantined and deleted five copies of the same malicious HP installer artifact"
    },

    "EPVSWBNA": {
        "status": "CONFIRMED",
        "reason": "AV quarantined and deleted three malicious printer-directory files with distinct SHA256s"
    },

    # Shared recently-used.xbel artifact
    "EP3GALVS": {
        "status": "LIKELY_COMPROMISED",
        "reason": "Repeated AV remediation of shared malicious recently-used.xbel artifact"
    },

    "EPAX5P5D": {
        "status": "LIKELY_COMPROMISED",
        "reason": "Repeated AV remediation of shared malicious recently-used.xbel artifact"
    },

    "EPC2L3UH": {
        "status": "LIKELY_COMPROMISED",
        "reason": "Repeated AV remediation of shared malicious recently-used.xbel artifact"
    },

    "EPDRB236": {
        "status": "LIKELY_COMPROMISED",
        "reason": "AV remediation of shared malicious recently-used.xbel artifact"
    },

    "EPFQSCDV": {
        "status": "LIKELY_COMPROMISED",
        "reason": "AV remediation of shared malicious recently-used.xbel artifact"
    },

    "EPJYEC7F": {
        "status": "LIKELY_COMPROMISED",
        "reason": "Repeated AV remediation of shared malicious recently-used.xbel artifact"
    },

    "EPMQTKSL": {
        "status": "LIKELY_COMPROMISED",
        "reason": "AV remediation of shared malicious recently-used.xbel artifact"
    },

    "EPR4BEDS": {
        "status": "LIKELY_COMPROMISED",
        "reason": "AV remediation of shared malicious recently-used.xbel artifact"
    },

    # Weak evidence
    "EPLFOXSS": {
        "status": "SUSPICIOUS",
        "reason": "AV repeatedly attempted to handle Evolution mail artifact, but no successful processing or quarantine was recorded"
    }
}


# Build endpoint-level summary
rows = []

for endpoint_id, info in classification.items():

    endpoint_data = av[av["endpoint_id"] == endpoint_id]

    if endpoint_data.empty:
        continue

    for _, row in endpoint_data.iterrows():
        rows.append({
            "endpoint_id": endpoint_id,
            "status": info["status"],
            "original_file": row["original_file"],
            "av_events": row["av_events"],
            "actions": row["actions"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "location": row["location"],
            "reason": info["reason"]
        })


result = pd.DataFrame(rows)

# Save detailed classification
output_file = OUTPUT_DIR / "final_endpoint_classification.csv"
result.to_csv(output_file, index=False)

print("=" * 80)
print("FINAL ENDPOINT CLASSIFICATION")
print("=" * 80)

# Endpoint-level status
endpoint_summary = (
    result[["endpoint_id", "status", "reason"]]
    .drop_duplicates()
    .sort_values(["status", "endpoint_id"])
)

print("\nEndpoint status:\n")
print(endpoint_summary.to_string(index=False))

print("\n" + "=" * 80)
print("STATUS COUNTS")
print("=" * 80)

print(
    endpoint_summary["status"]
    .value_counts()
    .to_string()
)

print("\n" + "=" * 80)
print("CONFIRMED ENDPOINTS")
print("=" * 80)

confirmed = endpoint_summary[
    endpoint_summary["status"] == "CONFIRMED"
]

print(confirmed.to_string(index=False))

print("\n" + "=" * 80)
print("LIKELY COMPROMISED ENDPOINTS")
print("=" * 80)

likely = endpoint_summary[
    endpoint_summary["status"] == "LIKELY_COMPROMISED"
]

print(likely.to_string(index=False))

print("\n" + "=" * 80)
print("SUSPICIOUS ENDPOINTS")
print("=" * 80)

suspicious = endpoint_summary[
    endpoint_summary["status"] == "SUSPICIOUS"
]

print(suspicious.to_string(index=False))

print(f"\nSaved to: {output_file}")