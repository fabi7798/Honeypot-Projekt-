# High-Interaction-Honeypot – Langflow 1.8.1

## Projekt

Hochschule Bonn-Rhein-Sieg
Bachelor Cyber Security & Privacy
Wintersemester 2026/27
Projekt Honeypots – High-Interaction-Teil

## Ziel

Aufbau und Untersuchung eines High-Interaction-Honeypots
auf Basis der realen Webanwendung Langflow 1.8.1.

Im Mittelpunkt stehen die kontrollierte Untersuchung
von CVE-2026-33017, das HTTP-Logging und die
regelbasierte Erkennung auffälliger Anfragen.

## Architektur

- Langflow 1.8.1 als Webanwendung
- Docker Compose zur Containerverwaltung
- Nginx als Reverse Proxy
- HTTP-Logging mit eindeutiger Request-ID
- SQLite für Anwendungsdaten
- Separate SQLite-Datenbank für Detection
- Python-basierte Detection Pipeline

## Testumgebungen

### Lokale Testumgebung – Kali Linux

Die lokalen Experimente wurden mit Docker Compose
und Nginx durchgeführt.

Konfiguration: docker-compose.yml

Lokaler Zugriff: http://127.0.0.1:8080

### Hochschul-VM

Die VM verwendet eine separat gehärtete Konfiguration:

docker-compose.vm.yml

- Internes Docker-Netzwerk
- Keine veröffentlichten Container-Ports
- ReadOnlyRootFS für Langflow und Nginx
- AppArmor und NoNewPrivileges
- Eingeschränkte Linux-Capabilities
- CPU-, RAM- und Prozesslimits
- Deaktivierte Telemetrie
- Eingeschränkte CORS-Konfiguration

Die Detection Pipeline wurde auf der VM als
systemd-Dienst getestet. Die Einrichtung dieses
Dienstes und der Logrotation erfolgt separat
auf dem Host und ist nicht Bestandteil der
Docker-Compose-Datei.

Ein automatischer Neustart der Honeypot-Dienste
ist derzeit nicht aktiviert.

## Nachgewiesene Ergebnisse

### HTTP-Logging

- Erfolgreiche HTTP-Anfragen mit Status 200
- Request-ID in HTTP-Antwort und Nginx-Log
- Automatische Verarbeitung neuer Logeinträge

### Detection Pipeline

- Speicherung von HTTP-Requests in SQLite
- Regelbasierte Erkennung von HTTP-Fehlern
- Erkennung wiederholter Clientfehler
- Erfolgreicher Test der Nginx-Logrotation

Die Alerts sind Hinweise auf Auffälligkeiten,
keine Nachweise erfolgreicher Angriffe.

### Kontrollierter CVE-Test

In der isolierten lokalen Testumgebung wurde
CVE-2026-33017 untersucht.

Ergebnis:
- HTTP 200 und Job-ID
- Serverseitige Python-Codeausführung durch
  einen eindeutigen lokalen Marker nachgewiesen

Der CVE-Test wurde nicht auf der Hochschul-VM
wiederholt.

## Grenzen

- Ein HTTP-Status 200 unterscheidet nicht
  zuverlässig zwischen normalen und
  manipulierten Anfragen.
- Die Detection Pipeline erkennt keine
  beliebige erfolgreiche Codeausführung.
- bpftrace wurde separat überprüft.
- Eine automatische Zuordnung von Request-IDs
  zu internen Prozessereignissen besteht nicht.
- Die VM-Konfiguration wurde intern getestet,
  aber nicht für öffentliche Zugriffe freigegeben.

## Dokumentation

- docs/application-selection.md
- docs/high-interaction-summary.md
- docs/experiment-comparison.md
- docs/automatic-detection-pipeline.md
- docs/VM-Security-Audit-2026-11-16.md
- experiments/cve-2026-33017/README.md

## Sicherheit

Langflow 1.8.1 wird hier bewusst als verwundbare
Anwendung für autorisierte Forschung eingesetzt.

Keine öffentliche Freigabe vor der Genehmigung
des gemeinsamen Sicherheitskonzepts.

Zugangsdaten, private Schlüssel, Datenbanken,
Payloads und Laufzeitlogs gehören nicht in GitHub.

## Status

High-Interaction-Implementierung, grundlegende
VM-Sicherheitsprüfungen und interne Tests
erfolgreich abgeschlossen.

Die gemeinsame Integration, abschließende
Gruppenfreigabe und öffentliche Bereitstellung
sind davon getrennte Aufgaben.
