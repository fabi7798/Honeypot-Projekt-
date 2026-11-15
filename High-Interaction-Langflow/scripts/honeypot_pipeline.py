#!/usr/bin/env python3
"""High-Interaction Langflow honeypot: incremental Nginx log monitoring.

Only parses access logs; does not execute requests or exploit code.
Supports classic and request_id-enabled Nginx log lines and numbered
rename-based rotations (access.log.1, access.log.2, ...). No copytruncate.
"""

import argparse
import re
import sqlite3
import time
from datetime import datetime
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent  # installed in project/scripts/
DEFAULT_LOG = PROJECT / 'logs' / 'nginx' / 'access.log'
DEFAULT_DB = PROJECT / 'logs' / 'pipeline' / 'detection.sqlite3'
LOG_FORMAT = re.compile(
    r'(?P<ip>\S+) - \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
    r'(?: "(?P<xff>[^"]*)" request_id=(?P<request_id>\S+))?'
)


def prepare(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS checkpoints (
            file_id TEXT PRIMARY KEY, offset INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS requests (
            file_id TEXT NOT NULL, offset INTEGER NOT NULL,
            time_utc INTEGER NOT NULL, ip TEXT NOT NULL,
            method TEXT NOT NULL, path TEXT NOT NULL,
            status INTEGER NOT NULL, request_id TEXT NOT NULL,
            ua TEXT NOT NULL, xff TEXT NOT NULL,
            PRIMARY KEY(file_id, offset)
        );
        CREATE INDEX IF NOT EXISTS idx_requests_ip_time
            ON requests(ip, time_utc, status);
        CREATE TABLE IF NOT EXISTS alerts (
            file_id TEXT NOT NULL, offset INTEGER NOT NULL,
            rule TEXT NOT NULL, severity TEXT NOT NULL,
            ip TEXT NOT NULL, request_id TEXT NOT NULL,
            PRIMARY KEY(file_id, offset, rule)
        );
        CREATE TABLE IF NOT EXISTS behavior_alerts (
            file_id TEXT NOT NULL, offset INTEGER NOT NULL,
            rule TEXT NOT NULL, severity TEXT NOT NULL,
            ip TEXT NOT NULL, time_utc INTEGER NOT NULL,
            count_5m INTEGER NOT NULL, request_id TEXT NOT NULL,
            PRIMARY KEY(file_id, offset, rule)
        );
        CREATE INDEX IF NOT EXISTS idx_behavior_ip_time
            ON behavior_alerts(ip, time_utc);
    ''')


def log_candidates(log_path):
    folder = log_path.parent
    if not folder.is_dir():
        raise RuntimeError(f'Log directory does not exist: {folder}')
    paths = []
    for p in folder.iterdir():
        if not p.is_file():
            continue
        if p.name == log_path.name:
            paths.append((1, 0, p))
        elif re.fullmatch(re.escape(log_path.name) + r'\.\d+', p.name):
            suffix = int(p.name.rsplit('.', 1)[1])
            paths.append((0, -suffix, p))
    if not paths:
        raise RuntimeError(f'No uncompressed log file found: {log_path}')
    return [p for _, _, p in sorted(paths)]


def parse_line(line, file_id, offset):
    match = LOG_FORMAT.fullmatch(line)
    if match is None:
        raise ValueError(f'Unrecognized log format: {file_id}@{offset}')
    item = match.groupdict()
    request = item['request'].split(' ', 2)
    if len(request) != 3 or not request[2].startswith('HTTP/'):
        raise ValueError(f'Invalid HTTP request: {file_id}@{offset}')
    timestamp = int(datetime.strptime(item['time'], '%d/%b/%Y:%H:%M:%S %z').timestamp())
    return {
        'file_id': file_id, 'offset': offset,
        'time_utc': timestamp, 'ip': item['ip'],
        'method': request[0], 'path': request[1],
        'status': int(item['status']),
        'request_id': item['request_id'] or '',
        'ua': item['ua'], 'xff': item['xff'] or ''
    }


def process_request(db, r):
    inserted = db.execute('''
        INSERT OR IGNORE INTO requests
        (file_id,offset,time_utc,ip,method,path,status,request_id,ua,xff)
        VALUES (:file_id,:offset,:time_utc,:ip,:method,:path,:status,:request_id,:ua,:xff)
    ''', r).rowcount
    if not inserted:
        return (0, 0, 0)
    http_alert = behavior_alert = 0
    status = r['status']
    if status >= 500 or status in (403, 422):
        rule, severity = (('server_error', 'high') if status >= 500
                          else ('invalid_or_denied_request', 'medium'))
        http_alert = db.execute('''
            INSERT OR IGNORE INTO alerts
            (file_id,offset,rule,severity,ip,request_id)
            VALUES (?,?,?,?,?,?)
        ''', (r['file_id'], r['offset'], rule, severity,
              r['ip'], r['request_id'])).rowcount

    # 3 HTTP 4xx responses within 5 minutes per observed source IP.
    # These are indicators, NOT confirmed exploits or unique attackers.
    if 400 <= status < 500:
        count = db.execute('''
            SELECT COUNT(*) FROM requests
            WHERE ip=? AND status BETWEEN 400 AND 499
              AND time_utc BETWEEN ? AND ?
        ''', (r['ip'], r['time_utc'] - 300, r['time_utc'])).fetchone()[0]
        last = db.execute('''
            SELECT MAX(time_utc) FROM behavior_alerts
            WHERE ip=? AND rule='repeated_client_errors_5m'
        ''', (r['ip'],)).fetchone()[0]
        if count >= 3 and (last is None or r['time_utc'] - last >= 300):
            behavior_alert = db.execute('''
                INSERT OR IGNORE INTO behavior_alerts
                (file_id,offset,rule,severity,ip,time_utc,count_5m,request_id)
                VALUES (?,?, 'repeated_client_errors_5m', 'medium', ?,?,?,?)
            ''', (r['file_id'], r['offset'], r['ip'], r['time_utc'],
                  count, r['request_id'])).rowcount
    return (1, http_alert, behavior_alert)


def scan_once(db, log_path):
    counts = [0, 0, 0]
    # All inserts plus checkpoints are committed or rolled back together.
    with db:
        for path in log_candidates(log_path):
            stat = path.stat()
            file_id = f'{stat.st_dev}:{stat.st_ino}'
            checkpoint = db.execute(
                'SELECT offset FROM checkpoints WHERE file_id=?',
                (file_id,)
            ).fetchone()
            offset = checkpoint[0] if checkpoint else 0
            if stat.st_size < offset:
                raise RuntimeError(f'Truncation detected: {path}')
            with path.open('rb') as stream:
                stream.seek(offset)
                while True:
                    beginning = stream.tell()
                    raw = stream.readline()
                    if not raw or not raw.endswith(b'\n'):
                        break  # Wait for incomplete line to finish.
                    line = raw.decode('utf-8', errors='replace').rstrip('\r\n')
                    delta = process_request(db, parse_line(line, file_id, beginning))
                    counts = [a + b for a, b in zip(counts, delta)]
                    offset = stream.tell()
            db.execute('''
                INSERT INTO checkpoints(file_id,offset) VALUES (?,?)
                ON CONFLICT(file_id) DO UPDATE SET offset=excluded.offset
            ''', (file_id, offset))
    return counts


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--log', type=Path, default=DEFAULT_LOG,
                     help='Nginx access.log path (default: project/logs/nginx/access.log)')
    cli.add_argument('--db', type=Path, default=DEFAULT_DB,
                     help='SQLite state DB (default: project/logs/pipeline/detection.sqlite3)')
    cli.add_argument('--interval', type=float, default=2.0,
                     help='Polling period in seconds (default: 2)')
    cli.add_argument('--once', action='store_true', help='Process available logs, then exit')
    args = cli.parse_args()
    if args.interval <= 0:
        cli.error('--interval must be positive')
    if args.db.resolve() == args.log.resolve():
        cli.error('Database and log paths must be different')
    try:
        args.db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(args.db, timeout=20) as db:
            prepare(db)
            while True:
                new, http, behavior = scan_once(db, args.log)
                if args.once or new:
                    print(f'New requests: {new} | HTTP alerts: {http} | '
                          f'Behavior alerts: {behavior}', flush=True)
                if args.once:
                    return
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print('\nMonitor stopped.', flush=True)
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
        raise SystemExit(f'PIPELINE STOPPED: {exc}')


if __name__ == '__main__':
    main()
