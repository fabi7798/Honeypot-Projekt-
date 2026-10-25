import re
import csv
from pathlib import Path

log_file = Path("logs/nginx/access.log")
baseline_file = Path("logs/baseline/access-log-start-line.txt")
out_file = Path("logs/new_requests.csv")

start_line = int(baseline_file.read_text().strip())

pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) HTTP/[^"]+" '
    r'(?P<status>\d+) (?P<size>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

lines = log_file.read_text(errors="ignore").splitlines()

new_lines = lines[start_line:]

rows = []

for line in new_lines:
    m = pattern.match(line)
    if not m:
        continue

    path = m.group("path")

    if (
        "/api/v1/build_public_tmp/" in path
        or "/api/v1/flows/public_flow/" in path
    ):
        rows.append(m.groupdict())

with out_file.open("w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["ip", "time", "method", "path", "status", "size", "referer", "ua"]
    )
    writer.writeheader()
    writer.writerows(rows)

print("===== NEW TRAFFIC =====")
print("Baseline line:", start_line)
print("Current log lines:", len(lines))
print("New raw lines:", len(new_lines))
print("Relevant new requests:", len(rows))

if rows:
    for r in rows:
        print(
            f'{r["time"]} | {r["ip"]} | '
            f'{r["method"]} {r["path"]} | '
            f'{r["status"]} | {r["ua"]}'
        )

print(f"\nSaved to {out_file}")
