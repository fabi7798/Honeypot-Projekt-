import csv
from collections import Counter
from pathlib import Path

src = Path("logs/new_requests.csv")
classified = Path("logs/new_classified_requests.csv")
alerts_file = Path("logs/new_alerts.csv")

with src.open() as f:
    rows = list(csv.DictReader(f))

# -----------------------------
# Classification
# -----------------------------

classified_rows = []

for row in rows:
    path = row["path"]
    status = int(row["status"])

    event = "other"
    severity = "low"
    note = "Unclassified request"

    if "/api/v1/flows/public_flow/" in path:
        event = "public_flow_read"

        if status == 200:
            severity = "info"
            note = "Public flow metadata read successfully"
        else:
            severity = "medium"
            note = "Failed public flow read"

    elif "/api/v1/build_public_tmp/" in path:
        event = "public_flow_build"

        if status == 200:
            severity = "info"
            note = "Public flow build request accepted"
        elif status == 400:
            severity = "low"
            note = "Malformed or incomplete public build request"
        elif status == 403:
            severity = "medium"
            note = "Public build request denied"
        elif status == 422:
            severity = "medium"
            note = "Invalid request parameters"
        elif status >= 500:
            severity = "high"
            note = "Server-side error while processing public build"

    row["event"] = event
    row["severity"] = severity
    row["note"] = note

    classified_rows.append(row)

fieldnames = [
    "ip", "time", "method", "path",
    "status", "size", "referer", "ua",
    "event", "severity", "note"
]

with classified.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(classified_rows)

# -----------------------------
# Detection
# -----------------------------

alerts = []

for r in classified_rows:
    status = int(r["status"])

    if status >= 500:
        alerts.append({
            "time": r["time"],
            "ip": r["ip"],
            "rule": "server_error",
            "severity": "high",
            "details": f'{r["method"]} {r["path"]} returned {status}'
        })

    elif status in {403, 422}:
        alerts.append({
            "time": r["time"],
            "ip": r["ip"],
            "rule": "invalid_or_denied_request",
            "severity": "medium",
            "details": f'{r["method"]} {r["path"]} returned {status}'
        })

failed = Counter(
    r["ip"]
    for r in classified_rows
    if int(r["status"]) >= 400
)

for ip, count in failed.items():
    if count >= 3:
        alerts.append({
            "time": "-",
            "ip": ip,
            "rule": "repeated_failures",
            "severity": "high",
            "details": f"{count} failed requests observed"
        })

alert_fields = ["time", "ip", "rule", "severity", "details"]

with alerts_file.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=alert_fields)
    writer.writeheader()
    writer.writerows(alerts)

# -----------------------------
# Summary
# -----------------------------

print("===== NEW TRAFFIC ANALYSIS =====")
print("Requests:", len(classified_rows))
print("Alerts:", len(alerts))

if classified_rows:
    print("\nBy status:")
    for status, count in Counter(r["status"] for r in classified_rows).most_common():
        print(f"  {status}: {count}")

    print("\nBy event:")
    for event, count in Counter(r["event"] for r in classified_rows).most_common():
        print(f"  {event}: {count}")

if alerts:
    print("\nAlerts:")
    for a in alerts:
        print(
            f'  {a["severity"].upper():6} | '
            f'{a["ip"]} | {a["rule"]} | {a["details"]}'
        )
else:
    print("\nNo alerts detected.")

print("\nFiles:")
print(classified)
print(alerts_file)
