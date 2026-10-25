# Honeypot Detection Test

## Test date
04 October 2026

## Purpose

Verify that the honeypot telemetry pipeline can distinguish normal
Langflow public-flow traffic from intentionally suspicious test traffic.

## Baseline

The baseline was frozen at line 304 of:

logs/nginx/access.log

Traffic before this point is treated as setup and debugging traffic.

## Normal traffic test

A valid public flow request produced:

- HTTP 200
- public_flow_read
- public_flow_build
- no alerts

Result:

Requests: 2
Alerts: 0

## Suspicious traffic simulation

Three local POST requests were sent to different invalid flow identifiers:

- test-1
- test-2
- test-3

The requests used the custom User-Agent:

honeypot-probe/1.0

All three requests returned HTTP 422.

## Detection results

The detector generated:

- HIGH: repeated_failures
- MEDIUM: multiple_flow_targets
- LOW: unusual_user_agent

The classification layer also generated three MEDIUM
invalid_or_denied_request alerts and one HIGH repeated_failures alert.

## Interpretation

The traffic was synthetic laboratory test traffic, not a real attack.

The test demonstrates that the honeypot pipeline can:

1. record relevant Langflow requests,
2. isolate new traffic from the setup baseline,
3. classify requests,
4. detect repeated failed requests,
5. detect multiple targeted flow paths,
6. detect an unusual User-Agent,
7. generate structured alerts for later analysis.

## Current pipeline

Client
→ Nginx
→ Langflow
→ access.log
→ extraction
→ classification
→ behavior detection
→ alerts
