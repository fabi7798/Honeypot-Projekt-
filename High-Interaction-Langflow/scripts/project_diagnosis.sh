#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f docker-compose.vm.yml)

echo "=== HIGH-INTERACTION HONEYPOT ==="
echo "VM Deployment - Read-Only Diagnosis"

echo
echo "=== 1. COMPOSE CONFIGURATION ==="
"${COMPOSE[@]}" config --quiet
echo "Compose configuration: VALID"

echo
echo "=== 2. CONTAINER STATUS ==="
"${COMPOSE[@]}" ps --all

echo
echo "=== 3. CONTAINER SECURITY ==="

for service in langflow nginx; do
    echo "--- $service ---"

    cid=$("${COMPOSE[@]}" ps -q "$service")

    if [[ -z "$cid" ]]; then
        echo "Container not running"
        continue
    fi

    docker inspect "$cid" --format '
Status={{.State.Status}}
Privileged={{.HostConfig.Privileged}}
ReadOnlyRootFS={{.HostConfig.ReadonlyRootfs}}
SecurityOpt={{json .HostConfig.SecurityOpt}}
CapDrop={{json .HostConfig.CapDrop}}
PublishedPorts={{json .HostConfig.PortBindings}}
MemoryBytes={{.HostConfig.Memory}}
PidsLimit={{.HostConfig.PidsLimit}}
'
done

echo
echo "=== 4. DOCKER NETWORK ==="

cid=$("${COMPOSE[@]}" ps -q langflow)

if [[ -n "$cid" ]]; then
    network=$(docker inspect "$cid" \
        --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}')

    docker network inspect "$network" \
        --format 'Network={{.Name}} Internal={{.Internal}}'
else
    echo "Network runtime check unavailable"
fi

echo
echo "=== 5. DETECTION SERVICE ==="
systemctl is-active honeypot-monitor.service || true
systemctl is-enabled honeypot-monitor.service || true

echo
echo "=== 6. LOGGING ==="

if [[ -f logs/nginx/access.log ]]; then
    echo "Nginx access.log: PRESENT"
else
    echo "Nginx access.log: NOT FOUND"
fi

if [[ -f logs/pipeline/detection.sqlite3 ]]; then
    echo "Detection SQLite: PRESENT"
else
    echo "Detection SQLite: NOT FOUND"
fi

echo
echo "=== DIAGNOSIS COMPLETED ==="
