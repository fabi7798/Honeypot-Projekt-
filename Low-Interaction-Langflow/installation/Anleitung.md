# Langflow-Honeypot mit Docker betreiben

Anleitung, was beim Betrieb mit Docker zu tun ist: bauen, absichern, starten, prüfen, warten.
Ausgangspunkt ist ein Ordner mit `honeypot.py` und `Dockerfile`.

> Den Honeypot nur auf einem **isolierten Host** (eigene VM / eigener Rechner / eigenes VLAN) betreiben,
> nicht auf dem Arbeitsrechner und nicht in einem Netz mit internen Systemen.

---

## 1. Voraussetzungen

- Linux-Host mit Docker (`docker --version`)
- `sudo`-Rechte (für Datenordner-Rechte und Firewall-Regel)
- Datei `honeypot.py` und `Dockerfile` im gleichen Ordner
- Kein echtes Passwort, kein SSH-Schlüssel und keine sensiblen Daten auf dem Host

---

## 2. Image bauen

Im Projektordner:

```bash
docker build --pull -t langflow-honeypot .
```

`--pull` holt das aktuelle Python-Basis-Image. Bei jedem späteren Update erneut ausführen.

Optional eine `.dockerignore` anlegen, damit keine Logs ins Image kopiert werden:

```
data/
.git
__pycache__/
```

---

## 3. Datenordner vorbereiten

Der Container läuft als Benutzer mit UID `10001` und schreibt in `/data`.
Der Ordner auf dem Host muss diesem Benutzer gehören:

```bash
mkdir -p ~/honeypot-data
sudo chown 10001 ~/honeypot-data
```

Darin entstehen später:

```
~/honeypot-data/
  events.jsonl      <- Log, eine JSON-Zeile pro Request
  payloads/         <- gespeicherte Request-Bodies (Dateiname = SHA-256)
```

---

## 4. Eigenes Netz und ausgehenden Verkehr sperren

Das ist die wichtigste Schutzmaßnahme: Selbst wenn jemand den Container kompromittiert,
kann er keine Verbindungen nach draußen aufbauen.

```bash
docker network create --subnet 172.30.0.0/24 hpnet
sudo iptables -I DOCKER-USER -s 172.30.0.0/24 -m conntrack --ctstate NEW -j DROP
```

- Eingehende Verbindungen (Angreifer -> Honeypot) und deren Antworten funktionieren weiter.
- Neue ausgehende Verbindungen des Containers werden verworfen (auch DNS).
- Die iptables-Regel geht beim **Neustart des Hosts verloren**. Dauerhaft machen:

```bash
sudo apt install iptables-persistent     # Debian/Ubuntu/Kali
sudo netfilter-persistent save
```

Regel prüfen:

```bash
sudo iptables -L DOCKER-USER -n --line-numbers
```

---

## 5. Container gehärtet starten

```bash
docker run -d --name lf-hp \
  --network hpnet \
  --restart unless-stopped \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 100 \
  --memory 256m --cpus 0.5 \
  --log-opt max-size=10m --log-opt max-file=3 \
  -p 7860:7860 \
  -v ~/honeypot-data:/data \
  langflow-honeypot
```

| Option | Wirkung |
| --- | --- |
| `--network hpnet` | Container hängt im Netz mit gesperrtem Egress |
| `--restart unless-stopped` | Startet nach Neustart des Hosts wieder |
| `--read-only` | Dateisystem des Containers ist schreibgeschützt, nur `/data` ist beschreibbar |
| `--tmpfs /tmp` | Kleiner, nicht ausführbarer Temp-Bereich im RAM |
| `--cap-drop ALL` | Entfernt alle Linux-Capabilities |
| `no-new-privileges` | Verhindert Rechteausweitung |
| `--pids-limit`, `--memory`, `--cpus` | Begrenzen Ressourcen gegen Überlastung |
| `--log-opt max-size` / `max-file` | Docker-Logs wachsen nicht unbegrenzt (3 x 10 MB) |
| `-p 7860:7860` | Langflow-Standardport (Host:Container) |

Anderer Port von außen, z. B. 8080 -> Honeypot:

```bash
-p 8080:7860
```

Nur auf eine bestimmte Host-Adresse lauschen (statt auf allen):

```bash
-p 203.0.113.10:7860:7860
```

### Nicht verwenden

- `--privileged`
- `-v /var/run/docker.sock:/var/run/docker.sock` (würde Root auf dem Host geben)
- `--network host`
- Mounts von persönlichen Ordnern (Home, `.ssh`, ...) außer `~/honeypot-data`

---

## 6. Firewall / Router

- Auf dem Host Port 7860 (oder deinen gewählten Port) von außen erlauben, alles andere wie gewohnt sperren.
- Hinter einem Heimrouter: Portweiterleitung auf den Honeypot-Host einrichten.
- Den Honeypot-Host **nicht** in dein normales Heimnetz legen, sondern in ein eigenes VLAN / Gast-Netz / DMZ,
  damit ein Ausbruch keine anderen Geräte erreicht.
- Zugriff für die Verwaltung (SSH) auf dem Host nur von deiner IP erlauben.

---

## 7. Prüfen, dass alles funktioniert

### Läuft der Container?

```bash
docker ps --filter name=lf-hp
docker logs lf-hp
```

### Antwortet der Honeypot?

```bash
curl -si http://127.0.0.1:7860/api/v1/version
```

Erwartet: `200` und `{"version":"1.8.1","main_version":"1.8.1","package":"Langflow"}`

### Weitere Testrequests

```bash
B=http://127.0.0.1:7860
curl -s  $B/api/v1/auto_login
curl -s -X POST $B/api/v1/login -d 'username=admin&password=hunter2'
curl -s -X POST $B/api/v1/validate/code -H 'Content-Type: application/json' -d '{"code":"import os"}'
curl -si $B/irgendwas        # 404
```

### Wird geloggt?

```bash
jq -r '[.ts,.src_ip,.method,.path,.status,.event] | @tsv' ~/honeypot-data/events.jsonl
ls ~/honeypot-data/payloads/
```

### Ist der Egress wirklich gesperrt?

```bash
docker exec lf-hp python -c "import urllib.request; urllib.request.urlopen('http://1.1.1.1', timeout=5)"
```

Erwartet: Fehler / Timeout. Kommt eine Antwort, ist die iptables-Regel aus Abschnitt 4 nicht aktiv.

### Sind die Härtungen aktiv?

```bash
docker inspect lf-hp --format 'ReadOnly={{.HostConfig.ReadonlyRootfs}} CapDrop={{.HostConfig.CapDrop}} SecOpt={{.HostConfig.SecurityOpt}}'
```

Erwartet: `ReadOnly=true`, `CapDrop=[ALL]`, `SecOpt=[no-new-privileges]`.

---

## 8. Laufender Betrieb

| Aufgabe | Befehl |
| --- | --- |
| Status | `docker ps --filter name=lf-hp` |
| Live-Logs | `docker logs -f lf-hp` |
| Anhalten | `docker stop lf-hp` |
| Starten | `docker start lf-hp` |
| Neustart | `docker restart lf-hp` |
| Live-Events aus Datei | `tail -f ~/honeypot-data/events.jsonl` |

Auswertung:

```bash
# Zugangsdaten
jq -r 'select(.event=="login_attempt") | [.src_ip,.credentials.username,.credentials.password] | @tsv' ~/honeypot-data/events.jsonl

# Code-Payloads (validate/code) mit Hash
jq -r 'select(.event=="validate_code") | [.ts,.src_ip,.body_sha256] | @tsv' ~/honeypot-data/events.jsonl

# Häufigste Quell-IPs
jq -r '.src_ip' ~/honeypot-data/events.jsonl | sort | uniq -c | sort -rn | head
```

---

## 9. Update

Nach Änderungen an `honeypot.py` oder für neue Python-Sicherheitsupdates:

```bash
docker build --pull -t langflow-honeypot .
docker stop lf-hp && docker rm lf-hp
# dann den Startbefehl aus Abschnitt 5 erneut ausführen
```

Der Datenordner `~/honeypot-data` bleibt erhalten, da er nicht im Container liegt.

---

## 10. Logs und Payloads verwalten

- `events.jsonl` und `payloads/` wachsen dauerhaft. Regelmäßig prüfen:

```bash
du -sh ~/honeypot-data
df -h
```

- Logrotation einrichten, z. B. `/etc/logrotate.d/langflow-honeypot`:

```
/home/DEINUSER/honeypot-data/events.jsonl {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    copytruncate
}
```

- Alte Auswertungen und Payloads nach Analyse sichern oder löschen.
- **Dateien in `payloads/` nie ausführen oder öffnen** (potenzielle Malware). Nur ansehen (`less`, `cat`),
  Hash (`sha256sum`) in Threat-Intel-Diensten nachschlagen.
- **Den Datenordner nicht ins Git-Repository committen** (`data/` in `.gitignore`).
  Er enthält echte IP-Adressen, Zugangsdaten und Malware.

---



## 11. Aufräumen / Deinstallieren

```bash
docker stop lf-hp && docker rm lf-hp
docker rmi langflow-honeypot
docker network rm hpnet
sudo iptables -D DOCKER-USER -s 172.30.0.0/24 -m conntrack --ctstate NEW -j DROP
sudo netfilter-persistent save
```

Den Datenordner `~/honeypot-data` nur löschen, wenn die Logs nicht mehr gebraucht werden.
