# Baseline Experiment – High Interaction Honeypot

## Umgebung
- Anwendung: Langflow 1.8.1
- Reverse Proxy: Nginx
- Monitoring: bpftrace (eBPF)
- Umgebung: Docker auf Kali Linux

## Versuchsablauf
1. Automatischer Start der Prozessüberwachung.
2. Normaler HTTP-Request: GET /health_check.
3. Separater Kontrolltest mittels docker exec.
4. Speicherung der Monitoring-Ergebnisse.

## Ergebnisse
- HTTP-Status: 200
- Kontrollprozess: /bin/echo
- Prozessereignis erfolgreich erfasst.
- Zeitformat: UTC
- Logdatei: logs/monitoring/baseline-automated.log

## Bewertung
Die Prozessüberwachung innerhalb des Langflow-Containers
konnte von außerhalb des Containers erfolgreich getestet werden.

Der erfasste Prozess wurde durch einen separaten
docker-exec-Test gestartet und nicht durch den HTTP-Request.

Ein erfolgreicher Exploit wurde nicht nachgewiesen.
Eine kausale Zuordnung zwischen HTTP-Request und Prozessereignis
ist mit diesem Versuch nicht möglich.

## HTTP Request Tracking

Der Nginx-Reverse-Proxy wurde um eine Request-ID erweitert.

Die Request-ID wird:
- an Langflow über den Header X-Request-ID weitergegeben,
- in der HTTP-Antwort zurückgegeben,
- im Nginx-Access-Log gespeichert.

Die Konfiguration wurde durch Docker Compose dauerhaft eingebunden.

## Verifikation

Test: GET /health_check

HTTP-Status: 200

Request-ID:
858b47b72762af622d866fb129adbba2

Die Request-ID in der HTTP-Antwort stimmt mit der
Request-ID im Nginx-Access-Log überein.

Eine Zuordnung dieser Request-ID zu internen
Prozessereignissen wurde noch nicht nachgewiesen.
