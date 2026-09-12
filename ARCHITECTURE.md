# SentinelX — System Architecture & Engineering Specification

## 1. System Overview

**SentinelX** is an Autonomous Security Operations Center (SOC) and Mini-SIEM platform engineered for real-time security telemetry ingestion, automated threat detection, risk-based prioritization, incident correlation, evidence-grounded AI forensic investigation, reversible containment, and stakeholder alerting.

The platform provides a centralized command-and-control interface designed for security analysts and SOC leads to rapidly detect, triage, investigate, and remediate cyber threats with complete auditability and zero destructive side effects.

---

## 2. Technology Stack

SentinelX is built exclusively with verified, lightweight, and resilient open-source technologies:

- **Core Runtime**: Python 3.14 (Virtual Environment in `./venv`)
- **Presentation Layer**: Streamlit (v1.x) with custom responsive HTML5/CSS3 glassmorphic design system
- **Database Engine**: SQLite 3 configured with Write-Ahead Logging (`PRAGMA journal_mode = WAL`), `PRAGMA synchronous = NORMAL`, and `PRAGMA busy_timeout = 15000`
- **AI Copilot**: Google Gemini API via official `google-genai` Python SDK (`gemini-3.6-flash`) with structured deterministic fallback
- **Alerting & Notification**: Telegram Bot API via standard HTTP POST (`requests`) with HTML formatting
- **Automation & Auto-Start**: PowerShell 5.1/7 with Windows Task Scheduler COM interfaces (`Schedule.Service`)
- **Public Ingress / Tunneling**: Cloudflare Quick Tunnel (`cloudflared`) providing temporary HTTPS ingress
- **Testing Framework**: `pytest` (v9.x) with custom fixtures and end-to-end integration tests

---

## 3. Frontend Architecture

The user interface is structured as an analyst-first security operations console:

### Presentation Architecture
- **Primary Orchestrator**: `app.py` manages session state, route rendering, filter controls, and analyst action triggers.
- **Design System & Theme**: `services/ui_theme.py` encapsulates the visual tokens, custom CSS layout rules, responsive breakpoints, and reusable UI components:
  - **Color Palette**: Cyber navy (`#080e1a`), deep panel background (`#0d1527`), bright cyan (`#00f0ff`), electric blue (`#00a8ff`), and semantic severity tokens (Critical `#ff2a6d`, High `#ff6b35`, Medium `#ffb800`, Low `#00e5a3`).
  - **Glassmorphism**: Translucent card backdrops with `rgba(13, 21, 39, 0.72)` fill, `1px solid rgba(0, 240, 255, 0.16)` borders, and multi-layer drop shadows.
  - **Typography**: Clean monospace and geometric sans-serif stack (`Inter`, `JetBrains Mono`, `Segoe UI`).
  - **Responsive Layout**: CSS `@media (max-width: 768px)` rules that stack KPI cards vertically, collapse side navigation, and enable horizontal touch-scrolling on wide telemetry tables.

### Consoles & Pages
1. **Login Gateway**: Secure authentication portal for Admin and SOC Analyst roles with zero credential leakage.
2. **SOC Dashboard**: Real-time KPI metrics (Active Incidents, Critical Threats, Events Ingested, Contained Sources), threat severity distribution, and recent security alerts.
3. **Live Events**: Real-time security telemetry feed with filtering by event type, status, and source IP.
4. **Security Alerts**: Triaged detections with severity scores, MITRE ATT&CK technique tags, and raw trigger evidence.
5. **Incidents Management**: Correlated threat dossiers displaying threat actor timelines, IOC extraction, AI Copilot investigation, and one-click containment controls.
6. **MITRE ATT&CK Matrix**: Interactive visualization mapping observed detections against enterprise MITRE techniques and tactics.
7. **Audit Logs & Containment**: Immutable trail of analyst actions, containment blocks, reversals, and system events.

---

## 4. Backend & Business Logic

### Database Layer (`database/database.py`)
- Manages connection lifecycle with WAL concurrency to prevent database locking under multi-threaded telemetry ingestion.
- Tables:
  - `security_events`: Raw ingested log events (timestamp, source IP, username, event type, action, status, message, severity, port).
  - `incidents`: Correlated security incidents with severity, risk score, status (OPEN, INVESTIGATING, CONTAINED, RESOLVED), and MITRE technique IDs.
  - `incident_events`: Many-to-many junction table mapping security events to incidents as forensic evidence.
  - `containment_actions`: Audit log of every IP block/unblock action with analyst ID, reason, and execution timestamp.
  - `blocked_sources`: Active network containment registry tracking currently blocked IP addresses.
  - `incident_status_history`: Timestamped state transitions for all managed incidents.
  - `users`: User credential records, roles, salt, and password hashes for internal analysts.

### Detection Engines (`detection/`)
1. **Brute Force (`detection/brute_force.py`)**: Identifies repeated failed authentication attempts from a single source within a sliding time window (threshold: >= 5 failed logins within 5 minutes). Mapped to MITRE T1110.
2. **Port Scan (`detection/port_scan.py`)**: Identifies rapid connection attempts across distinct destination ports from a single IP (threshold: >= 5 distinct ports within 2 minutes). Mapped to MITRE T1046.
3. **Privilege Escalation (`detection/privilege_escalation.py`)**: Detects unauthorized administrative group additions, role elevations, or elevation-of-privilege indicators. Mapped to MITRE T1078 / T1068.
4. **Suspicious Authentication (`detection/suspicious_auth.py`)**: Detects irregular logon patterns, after-hours access, or impossible travel logins. Mapped to MITRE T1078.
5. **Suspicious PowerShell (`detection/suspicious_powershell.py`)**: Detects obfuscated script execution, encoded commands (`-enc`), download cradles (`IEX`, `DownloadString`), and memory bypasses. Mapped to MITRE T1059.001.

### Risk Engine (`services/risk_engine.py`)
Calculates composite risk scores (0–100) and assigns discrete risk levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`):
Risk Score = min(100, (Severity Weight * 0.40) + (Event Frequency Weight * 0.35) + (Target Criticality Weight * 0.25))

### Incident Correlation
Aggregates incoming alerts sharing the same `source_ip` and threat category into a single master incident dossier to avoid alert fatigue. New alerts enrich existing open incidents by updating their event counts and linking fresh evidence.

### Remote Ingestion API (`api.py`)
- Independent multi-threaded HTTP service running on `0.0.0.0:8502` (configurable via `SENTINELX_INGEST_PORT`).
- **Authorized Demo / Test Endpoints**:
  - `GET /health`: Health check endpoint returning HTTP 200 and service metadata.
  - `POST /events`: Ingestion endpoint requiring `Authorization: Bearer <INGEST_TOKEN>` and `Content-Type: application/json`.
- Strict schema validation: Enforces valid IPv4 format, payload size limits (16 KB), allowed event types, and parameter length boundaries.

---

## 5. End-to-End Data Flow

```
Security Event Telemetry (API / Simulator)
       │
       ▼
Ingestion Validation & Sanitization (api.py)
       │
       ▼
Database Persistence (database/database.py -> security_events)
       │
       ▼
Detection Pipeline (detection/*.py)
       │
       ▼
Risk Scoring & Enrichment (services/risk_engine.py)
       │
       ▼
Alert Generation (Security Alerts Console)
       │
       ▼
Incident Correlation (Auto-grouping into incidents dossier)
       │
       ▼
Evidence Linking (incident_events mapping)
       │
       ▼
MITRE ATT&CK Mapping (Technique & Tactic tagging)
       │
       ▼
AI Forensic Investigation (services/ai_copilot.py)
       │
       ▼
Analyst Review & Recommended Containment Action
       │
       ▼
Safe Application Containment (services/containment.py)
       │
       ▼
Audit Logging (containment_actions & incident_status_history)
       │
       ▼
Telegram Incident Alert (services/telegram_alert.py)
```

---

## 6. File-by-File Responsibility Map

| File | Language | Layer | Purpose | Depends On | Used By | Tests |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `app.py` | Python | Presentation | Main Streamlit SOC console & page router | `database/`, `services/`, `detection/` | End-users, SOC Analysts | Unit/Integration |
| `api.py` | Python | API / Ingestion | Standalone HTTP event ingestion daemon | `database/database.py` | External forwarders, simulators | `tests/test_api.py` |
| `services/ui_theme.py` | Python / CSS | Presentation | Theme tokens, glassmorphism CSS, and KPI card components | None | `app.py` | `tests/test_ui_theme.py` |
| `services/auth.py` | Python | Security / Auth | PBKDF2-SHA256 password hashing & constant-time auth | `database/database.py` | `app.py` | `tests/test_auth.py` |
| `services/ai_copilot.py` | Python | AI / Forensic | Gemini-powered incident triage & structured fallback | `google.genai` SDK | `app.py` | `tests/test_ai_copilot.py` |
| `services/containment.py` | Python | Security Engine | Controlled IP containment & unblock mechanism | `database/database.py` | `app.py` | `tests/test_containment.py` |
| `services/risk_engine.py` | Python | Security Engine | Dynamic risk calculation & alert enrichment | None | `app.py`, Detection | `tests/test_risk_engine.py` |
| `services/forensics.py` | Python | Forensics | Chain-of-custody tracking & dossier export | `database/database.py` | `app.py` | `tests/test_forensics.py` |
| `services/security_posture.py` | Python | Analytics | Aggregate posture metrics & KPI calculations | `database/database.py` | `app.py` | `app.py` |
| `services/telegram_alert.py` | Python | Notification | Telegram Bot alerting with HTML escaping & deduplication | `requests` | `app.py` | `tests/test_telegram_updates.py` |
| `detection/brute_force.py` | Python | Detection | Detects repeated failed authentication attempts | None | `app.py`, Pipeline | `tests/detection/test_brute_force.py` |
| `detection/port_scan.py` | Python | Detection | Detects multi-port reconnaissance scanning | None | `app.py`, Pipeline | `tests/detection/test_port_scan.py` |
| `detection/privilege_escalation.py` | Python | Detection | Detects unauthorized privilege escalation events | None | `app.py`, Pipeline | `tests/detection/test_privilege_escalation.py` |
| `detection/suspicious_auth.py` | Python | Detection | Detects anomalous logons and after-hours access | None | `app.py`, Pipeline | `tests/detection/test_suspicious_auth.py` |
| `detection/suspicious_powershell.py` | Python | Detection | Detects obfuscated or malicious PowerShell execution | None | `app.py`, Pipeline | `tests/detection/test_suspicious_powershell.py` |
| `database/database.py` | Python / SQL | Persistence | SQLite connection pooling, schema initialization, and queries | `sqlite3` | Entire application | `tests/test_database.py` |
| `simulator/run_attack_demo.py` | Python | Simulator | Automated multi-stage attack simulation runner | `database/`, `detection/` | Demo operators | Manual / Integration |
| `setup_autostart.ps1` | PowerShell | DevOps | Windows Scheduled Task registrar for localhost:8501 | Windows Task Scheduler | System Admin | System verification |
| `remove_autostart.ps1` | PowerShell | DevOps | Unregisters auto-start task and cleans up processes | Windows Task Scheduler | System Admin | System verification |
| `start_public_sentinelx.ps1` | PowerShell | DevOps | Launches Cloudflare tunnel and local Streamlit instance | `cloudflared.exe` | Demo operators | System verification |
| `stop_sentinelx.ps1` | PowerShell | DevOps | Shuts down background tunnel and Streamlit processes | PowerShell | Demo operators | System verification |

---

## 7. Authentication & Role Separation

SentinelX enforces strict role-based access control (RBAC):
- **Admin Role (`ADMIN`)**:
  - Requires credentials configured securely via environment variable `SENTINELX_ADMIN_PASSWORD`.
  - Authenticated using constant-time string comparison (`secrets.compare_digest`) with single/double-quote resilience and whitespace trimming.
  - Granted full privileges: user management, system diagnostics, configuration inspection, containment execution, and incident state overrides.
- **SOC Analyst Role (`ANALYST`)**:
  - Authenticated using salted PBKDF2-HMAC-SHA256 password hashes stored in the SQLite `users` table.
  - Granted operational privileges: alert triage, incident investigation, AI copilot interaction, containment execution, and status updates.
- **Security Boundary**: Admin authentication completely bypasses the database hash path and mandates the private host environment variable. Zero secrets are hardcoded in application source code.

---

## 8. AI Copilot Integration & Safeguards

The SentinelX AI Copilot (`services/ai_copilot.py`) operates as an assistive analyst tool:
- **Evidence-Grounded**: All prompt payloads supplied to Google Gemini (`gemini-3.6-flash`) are strictly constructed from structured database evidence, including observed timestamps, event types, raw log messages, extracted IOCs, and MITRE tactic identifiers.
- **Safety Boundary**: The AI model **never** directly executes containment actions, firewall rules, or destructive commands. All recommendations require human analyst authorization and confirmation in the UI.
- **Deterministic Fallback**: If the Gemini API key is missing, network access is severed, or API quotas (HTTP 429) are exhausted, the system seamlessly activates a deterministic rule-based analysis engine. This fallback extracts IOCs, calculates attack timelines, and delivers structured response guidance without throwing unhandled exceptions.

---

## 9. Telegram Alerting Pipeline

The Telegram alerting module (`services/telegram_alert.py`) provides real-time stakeholder notifications:
- **Trigger Condition**: Alerts are dispatched exclusively when a newly correlated incident (`is_new_incident == True`) is created with `HIGH` or `CRITICAL` severity.
- **Incident Deduplication**: Subsequent events mapped to an already open incident update the incident dossier in SQLite but suppress duplicate Telegram alerts to prevent channel flooding.
- **Payload Sanitization**: Message bodies are HTML-escaped (`html.escape`) to prevent malformed formatting errors when processing raw shell commands or malicious payloads.
- **Resilience**: Network timeouts and Telegram API errors are caught and logged cleanly without blocking incident creation or disrupting the analyst UI.

---

## 10. Containment Architecture & Safety Controls

The containment subsystem (`services/containment.py`) provides safe, application-level isolation:
- **Controlled IP Blocking**: Records blocked source IPs in the `blocked_sources` table and logs a structured event in `containment_actions`.
- **Reversible Operations**: Analysts can unblock previously contained IPs at any time (`unblock_source_ip`). The operation verifies active state, toggles active flags, and appends an audit record.
- **Duplicate Prevention**: Attempting to block an already blocked IP returns `ALREADY_BLOCKED` safely.
- **Closed-Loop Verification**: The `verify_source_containment()` function inspects post-containment telemetry to verify whether the source IP continues to generate events after isolation.

---

## 11. Automated Testing Suite

The testing suite validates every layer of the application:
- **Unit & Integration Tests**: 58 automated test cases executed via `pytest`.
- **Test Categories**:
  - `tests/detection/`: All 5 detection engines (brute force, port scan, privilege escalation, suspicious auth, suspicious PowerShell).
  - `tests/test_auth.py`: Password hashing, constant-time comparison, quote resilience, self-healing database users.
  - `tests/test_containment.py`: Complete lifecycle of blocking, duplicate handling, unblocking, and post-containment verification.
  - `tests/test_ai_copilot.py` & `tests/test_gemini.py`: Gemini client initialization, connection, response schema, and fallback engine.
  - `tests/test_api.py`: Ingestion API routes, authentication, validation errors, and event insertion.
  - `tests/test_telegram_updates.py`: Alert formatting, HTML escaping, and dispatch handling.
  - `tests/test_ui_theme.py`: Design tokens, responsive CSS rules, KPI cards, and header renderers.
- **Validation Commands**:
  ```powershell
  . env\Scripts\python.exe -m py_compile app.py api.py
  . env\Scripts\python.exe -m compileall -q app.py api.py database detection services simulator tests
  . env\Scripts\python.exe -m pytest -q
  ```

---

## 12. Deployment & Startup Architecture

- **Local Production Execution**:
  - Service URL: `http://127.0.0.1:8501`
  - Automated Startup: Registered in Windows Task Scheduler as `SentinelX_AutoStart` (runs `-m streamlit run app.py --server.port 8501 --server.headless true --server.address 127.0.0.1` at user logon).
- **Public Demo Access (Temporary Quick Tunnel)**:
  - Managed via Cloudflare Quick Tunnel (`cloudflared tunnel --url http://127.0.0.1:8501`).
  - Active Task: `SentinelX_PublicTunnel` (exposing port 8501 via `trycloudflare.com`).
  - Classification: **Demo / Temporary Public Access** (URLs dynamically assign upon tunnel re-creation).
- **Remote Ingestion Endpoint**:
  - Host/Port: `http://localhost:8502/events`
  - Classification: **Authorized Demo / Test Endpoint**.
