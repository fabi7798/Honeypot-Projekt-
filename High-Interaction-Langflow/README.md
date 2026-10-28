# High-Interaction-Honeypot mit Langflow

## Projekt

Hochschule Bonn-Rhein-Sieg
Bachelor Cyber Security & Privacy
Wintersemester 2026/27
Modul: Projekt (Honeypots)

## Ziel

Aufbau und Untersuchung eines High-Interaction-Honeypots
auf Basis von Langflow 1.8.1.

Untersucht wird die Sicherheitslücke CVE-2026-33017
in einer lokalen, kontrollierten Testumgebung.

## Architektur

- Kali Linux als Testumgebung
- Docker Compose zur Containerverwaltung
- Langflow 1.8.1 als verwundbare Anwendung
- Nginx als Reverse Proxy
- HTTP-Logging mit Request-ID
- bpftrace zur Überwachung von Prozessstarts
- Persistente SQLite-Datenbank

## Netzwerk

Langflow befindet sich ausschließlich im internen
Docker-Netzwerk.

Nginx ist mit dem internen Netzwerk und einem separaten
Frontend-Netzwerk verbunden.

Der lokale Zugriff erfolgt über:

http://127.0.0.1:8080

## Experimente

### Baseline

Eine normale HTTP-Anfrage wurde an Langflow gesendet.

Ergebnis:
- HTTP 200
- Job-ID erhalten
- Request-ID im Nginx-Log dokumentiert

### Kontrollierter Sicherheitstest

CVE-2026-33017 wurde in einer isolierten
Testumgebung untersucht.

Ergebnis:
- HTTP 200
- Job-ID erhalten
- Serverseitige Python-Codeausführung durch
  einen eindeutigen lokalen Marker nachgewiesen

## Ergebnisse

Die normalen und die kontrolliert manipulierten
HTTP-Anfragen wurden im Nginx Access Log protokolliert.

Beide Anfragen lieferten HTTP 200.

Daher reicht der HTTP-Statuscode allein nicht aus,
um einen erfolgreichen Angriff zu erkennen.

## Dokumentation

- docs/high-interaction-summary.md
- docs/experiment-comparison.md
- docs/baseline-experiment.md
- docs/logging-plan.md

## Sicherheit

Dieses Projekt dient ausschließlich wissenschaftlichen
Testzwecken in einer lokalen Laborumgebung.

Die verwundbare Anwendung darf nicht ungeschützt
im öffentlichen Internet betrieben werden.

Datenbanken, Zugangsdaten, Backups und lokale Logs
werden nicht im Git-Repository gespeichert.

## Status

Technischer Aufbau: abgeschlossen
HTTP-Logging: funktionsfähig
Kontrollierter Exploit-Nachweis: erfolgreich
Auswertung: vorläufig abgeschlossen
Gruppenintegration und Abschlussdokumentation: ausstehend


## Installation und Start

### Voraussetzungen
- Docker Engine
- Docker Compose Plugin
- Linux-Testumgebung empfohlen

### Start

1. Repository klonen.
2. In das Verzeichnis High-Interaction-Langflow wechseln.
3. Container mit `docker compose up -d` starten.
4. Anwendung unter http://127.0.0.1:8080 aufrufen.
5. Containerstatus mit `docker compose ps` prüfen.

### Persistente Daten

Die SQLite-Datenbank wird in einem Docker-Volume gespeichert.
Die ursprüngliche lokale Versuchsdatenbank wird nicht mitgeliefert.

### Sicherheitshinweise

Langflow 1.8.1 ist absichtlich verwundbar.
Der Betrieb ist ausschließlich in einer autorisierten
und isolierten Laborumgebung vorgesehen.

Die Compose-Konfiguration wurde syntaktisch geprüft.
Ein vollständiger Neuinstallationstest steht noch aus.
