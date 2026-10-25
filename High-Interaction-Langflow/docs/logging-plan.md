# Logging-Konzept

Für das Honeypot-Experiment sollen mindestens folgende Daten erfasst werden:

1. Zeitpunkt des Requests
2. HTTP-Methode (z. B. GET oder POST)
3. Angeforderter Pfad / Endpoint
4. HTTP-Statuscode
5. User-Agent
6. Nginx Access Logs
7. Nginx Error Logs
8. Langflow Application Logs

Ziel:
Normale Requests und spätere Angriffsversuche sollen miteinander verglichen werden können.
