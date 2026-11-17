# Langflow 1.8.1 Low-Interaction-Honeypot

Einzelne Python-Datei, nur Standardbibliothek. Führt **nie** Code aus und startet keine Subprozesse.

## Start

```bash
python3 honeypot.py --port 7861 --data-dir ./data
# oder
docker build -t langflow-honeypot -f docker/Dockerfile .
docker run -d --name lf-hp -p 7861:7861 -v $PWD/data:/data langflow-honeypot
```

Optionen: `--host`, `--port`, `--data-dir`, `--trust-proxy` (X-Forwarded-For nur hinter eigenem Reverse Proxy), `--quiet`.

## Verhalten

|        Bereich        |                                Verhalten                            |                      Pfad                                   |
|-----------------------|---------------------------------------------------------------------|-------------------------------------------------------------|
| Fingerprinting        | Antwort wie Langflow 1.8.1                                          | `/`, `/health`, `/api/v1/version`                           |
| Login                 | Fake-Token (unsigniertes Pseudo-JWT), Zugangsdaten werden geloggt   | `/api/v1/auto_login`, `/api/v1/login`                       |
| Flow-Köder            | Fake-Flows mit festen IDs                                           | `/api/v1/build_public_temp/{flow_id}/flow` (auch `..._tmp`) |
| Fallen                | Body speichern, nichts ausführen                                    | `/api/v1/validate/code`                                     |
| Rest                  | 404                                                                 | alles andere                                                |

Flow-IDs stehen in `DECOY_FLOWS` am Anfang der Datei. Bekannte ID -> `200 {"job_id": ...}`, unbekannte -> 404.

## Logs

- `data/events.jsonl`: ein JSON-Objekt pro Request (Zeit, IP, Methode, Pfad, Header, Body-Vorschau, SHA-256, Status, `event`).
  Event-Typen: `request`, `auto_login`, `login_attempt` (mit `credentials`), `build_public_tmp`, `validate_code`.
- `data/payloads/<sha256>`: kompletter Body (max. 1 MiB), dedupliziert. **Nie ausführen**, Dateien als hochgradig bösartig behandeln.

Schnelle Auswertung:

```bash
jq -r 'select(.event=="validate_code") | [.ts,.src_ip,.body_sha256] | @tsv' data/events.jsonl
jq -r 'select(.event=="login_attempt") | [.src_ip,.credentials.username,.credentials.password] | @tsv' data/events.jsonl
```

## Betriebshinweise

- Auf isoliertem Host/VLAN betreiben, ohne echte Zugangsdaten, getrennt von Produktivnetzen. Egress sperren.
- Der Honeypot antwortet absichtlich nur mit Standard-Antworten; die exakten JSON-Strukturen (insbesondere `/api/v1/version`) bitte einmal gegen eine echte Langflow-1.8.1-Instanz vergleichen (`curl -si`), damit Header/Felder wirklich identisch sind.
- Hinter einem Proxy: `--trust-proxy` nur setzen, wenn der Proxy `X-Forwarded-For` selbst setzt, sonst können Angreifer die Quell-IP fälschen.
- Logrotation (z. B. `logrotate`) einplanen, die Payload-Ablage wächst.
