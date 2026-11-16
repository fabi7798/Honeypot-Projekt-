# Automatische HTTP- und Verhaltenserkennung (High-Interaction / Langflow)

**Status:** Lokal und auf der Hochschul-VM erfolgreich in einer isolierten Testumgebung überprüft. Keine öffentliche Freigabe.

## Zweck und Abgrenzung

`honeypot_pipeline.py` liest Nginx-Access-Logs, speichert neue HTTP-Ereignisse in einer separaten SQLite-Datenbank und erzeugt regelbasierte Hinweise auf auffällige HTTP-Antworten bzw. wiederholte Clientfehler. Die Auswertung löst selbst keine HTTP-Anfragen und keine Exploits aus. Ein Alarm ist **kein Beleg für einen erfolgreichen Angriff**.

Die Pipeline ist unabhängig von der SQLite-Datenbank der Langflow-Anwendung.

## Datenfluss

`Nginx access.log` → `inkrementeller Parser` → `SQLite requests` → `HTTP-/Verhaltensregeln` → `SQLite alerts / behavior_alerts`

Die Pipeline unterstützt das ältere Nginx-Logformat ohne Request-ID sowie das neuere Format mit `request_id=...`. Wo die Request-ID im Log fehlt, bleibt sie in der Datenbank leer. Das beobachtete IP-Feld ist die direkte Gegenstelle von Nginx und bei Docker-/Tunnel-Setups nicht zwingend die ursprüngliche Client-IP. Ungeprüfte `X-Forwarded-For`-Werte dürfen nicht als verlässliche Identität benutzt werden.

## Voraussetzungen

- Python 3 mit Standardbibliothek einschließlich `sqlite3` (keine externen Python-Pakete erforderlich).
- Nginx-Access-Log im projektbezogenen Format, passende Lese- und Schreibrechte.
- Script im Ordner `High-Interaction-Langflow/scripts/`.
- Separater, nicht öffentlich freigegebener Speicherort für SQLite-Daten und Logdateien.

## Benutzung

Aufruf aus `High-Interaction-Langflow/`:

```bash
# Vorhandene Logzeilen einmal verarbeiten und beenden
python3 scripts/honeypot_pipeline.py --once

# Fortlaufend prüfen (Standard: alle 2 Sekunden, Vordergrundprozess)
python3 -u scripts/honeypot_pipeline.py

# Abweichende Dateipfade explizit festlegen
python3 scripts/honeypot_pipeline.py --once \
  --log /pfad/zu/access.log \
  --db /pfad/zu/detection.sqlite3

# Prüfabstand anpassen
python3 -u scripts/honeypot_pipeline.py --interval 5
```

**Standardpfade:** `logs/nginx/access.log` und `logs/pipeline/detection.sqlite3`, jeweils relativ zum Projektverzeichnis. Auf der Hochschul-VM läuft die Pipeline als systemd-Dienst `honeypot-monitor.service` mit eingeschränkten Rechten. Der Dienst wurde manuell gestartet und ist aktiv. Der automatische Start nach einem VM-Neustart ist deaktiviert.

## Implementierte Regeln

| Regel | Bedingung | Einstufung |
|---|---|---|
| `server_error` | HTTP-Status ab 500 | `high` |
| `invalid_or_denied_request` | HTTP 403 oder 422 | `medium` |
| `repeated_client_errors_5m` | Mindestens drei HTTP-4xx-Antworten desselben beobachteten IP-Werts innerhalb von fünf Minuten | `medium` |

Für die Verhaltensregel wird frühestens fünf Minuten nach dem vorigen Verhaltenalarm desselben IP-Werts erneut ein Alarm erzeugt. HTTP 4xx umfasst auch legitime Fehlbedienungen; HTTP 5xx weist zunächst nur auf Serverfehler hin. Die Regeln sind **Heuristiken**, keine Angriffsnachweise.

## Persistenz und Log Rotation

Die SQLite-Datenbank hält `requests`, `alerts`, `behavior_alerts` und `checkpoints`. Datensatzschlüssel und Checkpoints vermeiden bei unveränderten Dateien eine erneute Verarbeitung. Der Parser wartet bei einer unvollständigen letzten Zeile bis zu deren Abschluss. Checkpoint und verarbeitete Einträge werden innerhalb einer SQLite-Transaktion aktualisiert.

Unterstützt werden vorhandene, nicht komprimierte, fortlaufend nummerierte Umbenennungen wie `access.log.1` zusammen mit `access.log`. Wenn eine Datei kleiner als ihr gespeicherter Offset wird, stoppt das Programm mit `Truncation detected`, statt stillschweigend weiterzumachen.

**Nicht vollständig abgedeckt:** `copytruncate`, komprimierte/gelöschte rotierte Dateien, vollständige Wiederherstellung bei fehlenden Logsegmenten, Inode-Wiederverwendung, dauerhafter Dienstbetrieb und Betriebsüberwachung. Bei vorzeitig entfernten rotierten Dateien kann Datenverlust nicht ausgeschlossen werden. Für einen Dauerbetrieb ist daher eine abgestimmte Log-Retention erforderlich.

## Verifizierte Ergebnisse

### Lokale Testumgebung

- HTTP-Requests wurden erfolgreich verarbeitet.
- HTTP- und Verhaltensregeln erzeugten strukturierte Alerts.
- Wiederholte Verarbeitung unveränderter Logs erzeugte keine Duplikate.
- Rotation durch Umbenennung wurde erfolgreich getestet.

### Hochschul-VM

- Langflow 1.8.1 und Nginx liefen isoliert in Docker.
- HTTP 200 und X-Request-ID wurden nachgewiesen.
- Die Detection Pipeline übernahm Requests automatisch in SQLite.
- Drei HTTP-404-Testrequests erzeugten einen Behavior Alert.
- Nginx Log Rotation wurde erfolgreich überprüft.
- Der systemd-Monitor war aktiv.
- Keine veröffentlichten Container-Ports.

### Aussagegrenze

Die Detection basiert auf HTTP-Statuscodes und einfachen
Verhaltensregeln. Ein Alert beweist keinen erfolgreichen Angriff.
Die CVE-Ausführung wurde in einem separaten lokalen Experiment
nachgewiesen, nicht automatisch durch diese Pipeline erkannt.

## Sicherheitsgrenzen und offene Arbeiten

- Eine erfolgreiche Ausnutzung von **CVE-2026-33017** kann bei HTTP 200 auftreten; die vorhandenen HTTP- und Verhaltensregeln belegen oder erkennen diesen Erfolg nicht zuverlässig. Für einen solchen Nachweis sind unabhängig erfasste Ausführungs-/Systemereignisse und eine überprüfbare Korrelation erforderlich.
- Keine Exponierung einer verwundbaren Langflow-Instanz über eine öffentliche Schnittstelle ohne abgestimmtes Sicherheitskonzept und Freigabe des Teams; zunächst nur lokal gebundener Zugang/SSH-Tunnel.
- Die Hochschul-VM ist ein gemeinsam genutztes System; Speicher, CPU, Ports, Log-Retention und Zugriffsrechte müssen mit den zuständigen Teammitgliedern abgestimmt werden.
- Bei Änderungen: Code-Review und Prüfung von `.gitignore`; keine Logdateien, Exploit-Artefakte, SQLite-Datenbanken oder Zugangsdaten veröffentlichen.

## Einordnung für die Gruppenarbeit

Der High-Interaction-Teil liefert technisch nachvollziehbare HTTP-Ereignisse und Regeln zur Voranalyse. Für die spätere gemeinsame Auswertung sollten Zeitstempel, Regel, beobachtete Quelle, Request-ID (sofern verfügbar), Logbeleg und Testkontext bereitgestellt werden. Die Interpretation der Angriffsergebnisse erfolgt im Gruppenvergleich.
