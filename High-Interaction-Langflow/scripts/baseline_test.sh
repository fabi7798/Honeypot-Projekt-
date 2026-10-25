#!/bin/bash
set -euo pipefail

PROJECT_DIR="$HOME/honeypot-project"
CONTAINER="honeypot-langflow"
LOG_DIR="$PROJECT_DIR/logs/monitoring"

mkdir -p "$LOG_DIR"

CONTAINER_ID=$(docker inspect -f '{{.Id}}' "$CONTAINER")
CGROUP_FILE="/sys/fs/cgroup/system.slice/docker-${CONTAINER_ID}.scope"
CGROUP_ID=$(stat -Lc '%i' "$CGROUP_FILE")

echo "CGROUP_ID=$CGROUP_ID"

echo "Starting monitoring..."

sudo env TZ=UTC timeout -s INT 15 bpftrace -e "
BEGIN { printf(\"MONITOR_STARTED\n\"); }
tracepoint:syscalls:sys_enter_execve /cgroup == $CGROUP_ID/ {
    time(\"%Y-%m-%d %H:%M:%S UTC \");
    printf(\"PID=%d FILE=%s\n\", pid, str(args.filename));
}
END { printf(\"MONITOR_STOPPED\n\"); }
" > "$LOG_DIR/baseline-automated.log" &

MONITOR_PID=$!

sleep 3

echo "Sending normal HTTP request..."
date -u '+HTTP_TEST_TIME=%Y-%m-%dT%H:%M:%SZ'
curl -sS -o /dev/null -w 'HTTP_STATUS=%{http_code}\n' \
    http://127.0.0.1:8080/health_check

echo "Running monitoring control test..."
docker exec "$CONTAINER" /bin/echo honeypot-control-test

wait "$MONITOR_PID" || true

echo "Monitoring results:"
cat "$LOG_DIR/baseline-automated.log"
