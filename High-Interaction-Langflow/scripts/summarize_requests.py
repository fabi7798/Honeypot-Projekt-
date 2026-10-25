import csv
from collections import Counter
from pathlib import Path

src = Path("logs/classified_requests.csv")

with src.open() as f:
    rows = list(csv.DictReader(f))

print("===== SUMMARY =====")
print("Total requests:", len(rows))

print("\nBy status:")
for k, v in Counter(r["status"] for r in rows).most_common():
    print(f"  {k}: {v}")

print("\nBy event:")
for k, v in Counter(r["event"] for r in rows).most_common():
    print(f"  {k}: {v}")

print("\nBy severity:")
for k, v in Counter(r["severity"] for r in rows).most_common():
    print(f"  {k}: {v}")

print("\nBy user-agent:")
for k, v in Counter(r["ua"] for r in rows).most_common():
    print(f"  {k}: {v}")

print("\nPotentially interesting events:")
for r in rows:
    if r["severity"] in {"medium", "high"}:
        print(
            f'  {r["time"]} | {r["ip"]} | '
            f'{r["method"]} {r["path"]} | '
            f'{r["status"]} | {r["note"]}'
        )
