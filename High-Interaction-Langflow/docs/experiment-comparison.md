# Vergleich: Normalanfrage und kontrollierter Angriff

## Versuchsaufbau
Langflow 1.8.1 mit Nginx Reverse Proxy und interner Docker-Netzwerkisolation.

## Baseline
Request-ID: 87a779a5b1556d1d8a30529c97bb0bdc
Logeintrag: 172.20.0.1 - - [25/Oct/2026:14:23:35 +0000] "POST /api/v1/build_public_tmp/8b7b16d6-65b7-4ebb-82d7-54f50d271df9/flow HTTP/1.1" 200 49 "-" "curl/8.20.0" "-" request_id=87a779a5b1556d1d8a30529c97bb0bdc
Ergebnis: HTTP 200 und Job-ID; keine Codeausführung nachgewiesen.

## Kontrollierter Angriff
Request-ID: ead06ecccadcfefd09ac2d1d037e634d
Logeintrag: 172.20.0.1 - - [25/Oct/2026:15:27:16 +0000] "POST /api/v1/build_public_tmp/8b7b16d6-65b7-4ebb-82d7-54f50d271df9/flow HTTP/1.1" 200 49 "-" "Python-urllib/3.13" "-" request_id=ead06ecccadcfefd09ac2d1d037e634d
Ergebnis: HTTP 200 und eindeutiger Ausführungsmarker im Container.

## Auswertung
Beide Anfragen wurden durch Nginx protokolliert.
Die HTTP-Statuscodes allein unterscheiden den Angriff nicht von der Baseline.
Der zusätzliche Ausführungsmarker bestätigt die serverseitige Codeausführung im Angriffstest.
Die Prozessüberwachung wurde unabhängig überprüft.
Eine direkte Request-ID-Zuordnung zu internen Python-Ausführungsschritten wurde nicht implementiert.

## Fazit
Der High-Interaction-Honeypot ermöglicht die Beobachtung echter Anwendungsverarbeitung.
Für die sichere Unterscheidung zwischen normalen und schädlichen Anfragen
reichen HTTP-Statuscodes und Standard-Access-Logs allein nicht aus.
