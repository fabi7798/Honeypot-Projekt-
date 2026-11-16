# High-Interaction Honeypot — VM Security Audit

Date: 2026-11-16
Project: Honeypots
Component: High-Interaction Honeypot (Langflow 1.8.1)
Status: Internal deployment verification completed

## Architecture
- Docker Compose deployment
- Langflow 1.8.1
- Nginx reverse proxy
- SQLite application storage
- Python-based Detection Pipeline
- Internal Docker bridge network

## Container Security
- Privileged: false (both containers)
- ReadOnlyRootFS: true (both containers)
- NoNewPrivileges: true (both containers)
- AppArmor: docker-default
- CapDrop: ALL (both containers)
- Langflow additional capabilities: none
- Nginx capabilities: CHOWN, SETUID, SETGID, NET_BIND_SERVICE

## Resource Limits
- Langflow: 2400 MiB, 256 PIDs
- Nginx: 128 MiB, 64 PIDs

## Network
- Docker network Internal=true
- No published container ports
- External deployment not authorized yet

## Application Verification
- Nginx -> Langflow: HTTP 200 OK
- X-Request-ID: verified
- SQLite logging pipeline: verified
- Detection service: active
- Behavior alert detection: verified
- Nginx log rotation: tested

## Application Hardening
- LANGFLOW_ALEMBIC_LOG_TO_STDOUT=true
- DO_NOT_TRACK=true
- CORS: local origins explicitly configured
- Allowed-origin preflight: HTTP 200
- Disallowed-origin preflight: HTTP 400

## Operational Notes
- Restart policy: no
- Containers do not restart automatically after reboot
- Detection service was not enabled for automatic startup
- Writable paths remain for application data, logs and tmpfs
- CORS does not replace network isolation

## Outstanding Requirements
- Final group security concept and approval
- Documentation review and internal handoff
- No public exposure before security approval

## Scope
This report documents observed deployment controls and
functional checks. It is not a penetration-test report
or proof that all vulnerabilities have been eliminated.
