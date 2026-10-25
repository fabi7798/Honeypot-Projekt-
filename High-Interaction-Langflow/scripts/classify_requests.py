import csv
from pathlib import Path

src = Path("logs/requests.csv")
dst = Path("logs/classified_requests.csv")

def classify(row):
    path = row["path"]
    status = row["status"]
    method = row["method"]

    event = "other"
    severity = "low"
    note = ""

    if "/api/v1/flows/public_flow/" in path:
        event = "public_flow_read"

        if status == "200":
            severity = "info"
            note = "Public flow metadata read successfully"
        else:
            severity = "medium"
            note = "Failed public flow read"

    elif "/api/v1/build_public_tmp/" in path:
        event = "public_flow_build"

        if status == "200":
            severity = "info"
            note = "Public flow build request accepted"

        elif status == "400":
            severity = "low"
            note = "Malformed or incomplete public build request"

        elif status == "403":
            severity = "medium"
            note = "Public build request denied"

        elif status == "422":
            severity = "medium"
            note = "Invalid request parameters"

        elif status.startswith("5"):
            severity = "high"
            note = "Server-side error while processing public build"

        else:
            severity = "low"
            note = "Unexpected public build response"

    return event, severity, note


with src.open() as f:
    reader = csv.DictReader(f)
    rows = list(reader)

fieldnames = list(reader.fieldnames) + ["event", "severity", "note"]

with dst.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()

    for row in rows:
        event, severity, note = classify(row)
        row["event"] = event
        row["severity"] = severity
        row["note"] = note
        writer.writerow(row)

print(f"Saved {len(rows)} classified rows to {dst}")
