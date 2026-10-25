import re
import csv
from pathlib import Path

log_file = Path("logs/nginx/access.log")
out_file = Path("logs/requests.csv")

pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) HTTP/[^"]+" '
    r'(?P<status>\d+) (?P<size>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

rows = []

for line in log_file.read_text(errors="ignore").splitlines():
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

print(f"Saved {len(rows)} rows to {out_file}")
