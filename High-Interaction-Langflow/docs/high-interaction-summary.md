# High-Interaction-Honeypot – Technische Zusammenfassung

## 1. Zielsetzung

Aufbau eines High-Interaction-Honeypots auf Basis von Langflow 1.8.1.

Ziel ist die Untersuchung einer bekannten Sicherheitslücke
(CVE-2026-33017) sowie die Protokollierung und Auswertung
kontrollierter HTTP-Anfragen.

## 2. Architektur

- Kali Linux als Versuchsumgebung
- Docker Compose zur Containerverwaltung
- Langflow 1.8.1 als verwundbare Webanwendung
- Nginx als Reverse Proxy
- HTTP-Logging mit eindeutiger Request-ID
- bpftrace zur Überwachung von Prozessstarts

## 3. Sicherheitsmaßnahmen

- Lokale Portfreigabe über 127.0.0.1:8080
- Internes Docker-Netzwerk für Langflow
- Separates Frontend-Netzwerk für Nginx
- Keine direkte Portfreigabe für Langflow
- Aktiviertes no-new-privileges
- Aktiviertes Seccomp
- Persistente SQLite-Datenbank
- Datenbanksicherung mit Integritätsprüfung

## 4. Experimentelle Durchführung

### Baseline

Eine normale HTTP-Anfrage wurde über Nginx
an Langflow weitergeleitet.

Ergebnis:
- HTTP 200
- Job-ID erhalten
- Request-ID im Nginx-Log nachgewiesen

### Kontrollierter Angriff

Ein HTTP-Request mit einem modifizierten
Custom Component wurde an Langflow gesendet.

Ergebnis:
- HTTP 200
- Job-ID erhalten
- Serverseitige Python-Codeausführung anhand
  einer eindeutigen Marker-Datei nachgewiesen

## 5. Logging und Auswertung

Beide Anfragen wurden im Nginx Access Log erfasst.

Der HTTP-Status 200 erlaubt keine zuverlässige
Unterscheidung zwischen normaler Anfrage und Angriff.

Die serverseitige Codeausführung wurde durch einen
separaten Ausführungsmarker bestätigt.

Die Prozessüberwachung mit bpftrace wurde unabhängig
getestet. Eine automatische Korrelation einzelner
HTTP-Request-IDs mit internen Python-Anweisungen
wurde nicht implementiert.

## 6. Grenzen des Experiments

- Durchführung ausschließlich in einer lokalen Testumgebung
- Kein Nachweis einer vollständigen Netzwerkisolation
- Keine Reverse Shell oder externe Kommunikation
- Kein Nachweis, dass jeder Angriff erkannt werden kann
- Keine automatische Erkennung beliebiger Python-Codeausführung

## 7. Fazit

Der High-Interaction-Honeypot konnte eine reale
serverseitige Codeausführung in Langflow 1.8.1 demonstrieren.

Die Kombination aus HTTP-Logging und zusätzlicher
interner Beobachtung liefert aussagekräftigere Ergebnisse
als die alleinige Auswertung von HTTP-Statuscodes.
