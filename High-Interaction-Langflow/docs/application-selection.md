# Anwendungsauswahl – High-Interaction Honeypot

## Gewählte Anwendung

Langflow 1.8.1

## Projektziel

Aufbau und Untersuchung eines High-Interaction-Honeypots
auf Basis einer realen Webanwendung.

## Gründe für die Auswahl

- Reale Webanwendung mit HTTP-API
- Reproduzierbare, kontrollierte Sicherheitsexperimente
- Untersuchung der Schwachstelle CVE-2026-33017
- Betrieb mit Docker Compose und Nginx
- Erfassung und Auswertung von HTTP-Anfragen

## Nachgewiesene Ergebnisse

In der lokalen Testumgebung wurden normale HTTP-Anfragen
und ein kontrollierter CVE-Test durchgeführt.

Der CVE-Test bestätigte eine serverseitige Python-Codeausführung
anhand eines eindeutigen lokalen Markers.

Auf der Hochschul-VM wurden die Anwendung, das HTTP-Logging,
die regelbasierte Detection Pipeline und die Container-Isolation
separat überprüft.

## Sicherheitsgrenzen

Die verwundbare Anwendung wird ausschließlich in einer
autorisierten, isolierten Testumgebung betrieben.

Eine öffentliche Freigabe erfolgt erst nach Genehmigung
des gemeinsamen Sicherheitskonzepts.
