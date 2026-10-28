import csv
from collections import Counter
from pathlib import Path

src = Path("logs/classified_requests.csv")
dst = Path("logs/alerts.csv")

with src.open() as f:
    rows = list(csv.DictReader(f))

alerts = []

# Rule 1: individual suspicious responses
for r in rows:
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

# Rule 2: repeated failed requests from the same IP
failed = Counter(
    r["ip"]
    for r in rows
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

fieldnames = ["time", "ip", "rule", "severity", "details"]

with dst.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(alerts)

print("===== ALERTS =====")
print("Total alerts:", len(alerts))

for a in alerts:
    print(
        f'{a["severity"].upper():6} | '
        f'{a["ip"]} | '
        f'{a["rule"]} | '
        f'{a["details"]}'
    )

print(f"\nSaved to {dst}")
