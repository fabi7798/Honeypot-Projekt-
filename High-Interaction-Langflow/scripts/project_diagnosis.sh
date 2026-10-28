#!/usr/bin/env bash
set -u

cd "$HOME/honeypot-project" || exit 1

REPORT="docs/project-diagnosis.txt"
mkdir -p docs

{
echo "=========================================="
echo "HONEYPOTS - TECHNISCHE BESTANDSAUFNAHME"
echo "=========================================="
date -u '+Zeitpunkt (UTC): %Y-%m-%dT%H:%M:%SZ'

echo
echo "=== 1. DOCKER-CONTAINER ==="
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'

echo
echo "=== 2. DOCKER-COMPOSE ==="
docker compose config --quiet && echo "Konfiguration gueltig"

echo
echo "=== 3. LANGFLOW-SICHERHEIT ==="
docker inspect honeypot-langflow --format \
'Privileged={{.HostConfig.Privileged}}
OOMKilled={{.State.OOMKilled}}
RestartCount={{.RestartCount}}
ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}}
NetworkMode={{.HostConfig.NetworkMode}}
SecurityOpt={{json .HostConfig.SecurityOpt}}
CapAdd={{json .HostConfig.CapAdd}}
CapDrop={{json .HostConfig.CapDrop}}'

echo
echo "=== 4. LANGFLOW-MOUNTS ==="
docker inspect honeypot-langflow --format \
'{{range .Mounts}}{{println .Type .Destination "RW=" .RW}}{{end}}'

echo
echo "=== 5. LANGFLOW-PROZESS ==="
docker exec honeypot-langflow sh -c \
'grep -E "^(Uid|Gid|CapEff|NoNewPrivs|Seccomp):" /proc/1/status'

echo
echo "=== 6. NGINX-KONFIGURATION ==="
docker exec honeypot-nginx nginx -t 2>&1

echo
echo "=== 7. REQUEST-ID-TEST ==="
curl --max-time 10 -sS -o /dev/null \
-w 'HTTP-Status: %{http_code}\n' \
-D /tmp/honeypot-diagnosis-headers \
http://127.0.0.1:8080/health_check
grep -i '^X-Request-ID:' /tmp/honeypot-diagnosis-headers
rm -f /tmp/honeypot-diagnosis-headers

echo
echo "=== 8. NGINX-LOGGING ==="
tail -n 2 logs/nginx/access.log

echo
echo "=== 9. MONITORING ==="
command -v bpftrace || true
command -v auditctl || true
systemctl is-active auditd || true

echo
echo "=== 10. MONITORING-DATEIEN ==="
find logs/monitoring -maxdepth 1 -type f \
-printf '%f (%s Bytes)\n' 2>/dev/null

echo
echo "=== 11. ARBEITSSPEICHER ==="
docker stats --no-stream --format \
'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' \
honeypot-langflow honeypot-nginx

echo
echo "=== 12. LETZTE LANGFLOW-FEHLER ==="
docker logs --tail 100 honeypot-langflow 2>&1 |
grep -E 'WORKER TIMEOUT|SIGKILL|code 134' |
tail -n 10 || true

echo
echo "=== 13. PROJEKTDATEIEN ==="
find scripts docs nginx -maxdepth 2 -type f \
-not -name '*.bak' -printf '%p\n' | sort

echo
echo "=========================================="
echo "DIAGNOSE ABGESCHLOSSEN"
echo "=========================================="
} | tee "$REPORT"
