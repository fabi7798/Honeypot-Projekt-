import csv
from collections import Counter, defaultdict
from pathlib import Path

src = Path("logs/new_classified_requests.csv")
out = Path("logs/behavior_alerts.csv")

with src.open() as f:
    rows = list(csv.DictReader(f))

alerts = []

# Group by IP
by_ip = defaultdict(list)
for r in rows:
    by_ip[r["ip"]].append(r)

for ip, items in by_ip.items():

    # Rule 1: many requests from same source
    if len(items) >= 10:
        alerts.append({
            "ip": ip,
            "rule": "high_request_volume",
            "severity": "medium",
            "details": f"{len(items)} requests observed"
        })

    # Rule 2: multiple failed requests
    failed = [r for r in items if int(r["status"]) >= 400]

    if len(failed) >= 3:
        alerts.append({
            "ip": ip,
            "rule": "repeated_failures",
            "severity": "high",
            "details": f"{len(failed)} failed requests"
        })

    # Rule 3: multiple different public build paths
    build_paths = {
        r["path"].split("?")[0]
        for r in items
        if "/api/v1/build_public_tmp/" in r["path"]
    }

    if len(build_paths) >= 3:
        alerts.append({
            "ip": ip,
            "rule": "multiple_flow_targets",
            "severity": "medium",
            "details": f"{len(build_paths)} different build targets requested"
        })

    # Rule 4: unusual user agents
    user_agents = Counter(r["ua"] for r in items)

    for ua, count in user_agents.items():
        known = (
            ua.startswith("Mozilla/")
            or ua.startswith("curl/")
        )

        if not known:
            alerts.append({
                "ip": ip,
                "rule": "unusual_user_agent",
                "severity": "low",
                "details": f"{count} requests using UA: {ua}"
            })

fields = ["ip", "rule", "severity", "details"]

with out.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(alerts)

print("===== BEHAVIOR DETECTION =====")
print("Requests analyzed:", len(rows))
print("Behavior alerts:", len(alerts))

for a in alerts:
    print(
        f'{a["severity"].upper():6} | '
        f'{a["ip"]} | '
        f'{a["rule"]} | '
        f'{a["details"]}'
    )

if not alerts:
    print("No suspicious behavior detected.")

print(f"\nSaved to {out}")
