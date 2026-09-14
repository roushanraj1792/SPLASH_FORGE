# SPLASH FORGE — Autonomous Security Operations Center (Mini-SIEM)

> **Enterprise AI-Assisted Threat Detection, Incident Orchestration & Containment Platform**

SPLASH FORGE is an autonomous Security Operations Center (SOC) and mini-SIEM platform engineered for real-time threat telemetry ingestion, deterministic rule correlation, explainable multi-factor risk scoring, automated host containment, and evidence-grounded AI copilot analysis.

---

## 🛡️ Core Architecture

SPLASH FORGE processes host and network telemetry through a 9-stage pipeline:

```
TELEMETRY INGESTION ──► DETECTION ENGINES ──► RISK SCORING ──► SECURITY ALERTS
                                                                    │
AUDIT LEDGER ◄── SAFE CONTAINMENT ◄── MITRE ATT&CK ◄── EVIDENCE ◄── INCIDENTS
```

1. **Telemetry Ingestion**: Continuous ingestion of Windows/Linux host events, authentication logs, and network connection telemetry.
2. **5 Heuristic Detection Engines**:
   - **Brute Force Detection** (T1110): Threshold-based detection on repeated failed authentication attempts.
   - **Port Scan Detection** (T1046): Multi-port horizontal scanning correlation.
   - **Suspicious PowerShell** (T1059.001): Command-line inspection for obfuscation (`-EncodedCommand`, `-ExecutionPolicy Bypass`).
   - **Privilege Escalation** (T1068): Detection of unprivileged to SYSTEM/Administrator transition sequences.
   - **Suspicious Authentication** (T1078): Time-anomaly and off-hours credential access detection.
3. **Multi-Factor Risk Scoring Engine**: Dynamic 0–100 risk score enrichment based on alert type, entity history, target criticality, and repeat frequency.
4. **Deterministic Evidence Linking**: Foreign-key traceable links preserving forensic chain-of-custody from raw events to correlated incidents.
5. **MITRE ATT&CK® Enterprise Matrix**: Ground-truth mapping of detections to MITRE Tactics and Techniques with direct reference links.
6. **Reversible Safe Containment**: Automated policy-driven host isolation with immutable audit trails.
7. **AI SOC Copilot**: Gemini-assisted threat narrative generation and analyst investigation guidance with deterministic rule-based fallback.

---

## 🖥️ Security Consoles

SPLASH FORGE provides 6 dedicated operational consoles:

- **Dashboard**: High-level SOC situational awareness, 4 core KPIs, visual SOC pipeline diagram, security posture scoring (0–100), threat landscape overview, and subsystem health indicators.
- **Live Events**: Real-time security telemetry feed with full-text search, event type filtering, severity badges, and monospace forensic formatting.
- **Security Alerts**: Prioritized detections enriched with risk scores, MITRE techniques, and confirmed evidence links.
- **Incidents**: Enterprise incident-response console with an active lifecycle pipeline stepper (`NEW` ➔ `TRIAGED` ➔ `INVESTIGATING` ➔ `CONTAINED` ➔ `RESOLVED`), containment triggers, and the Gemini AI Copilot.
- **MITRE ATT&CK**: Educational adversary technique matrix with end-to-end trace flows (`Detection` ➔ `Technique` ➔ `Tactic` ➔ `Evidence`).
- **Audit Logs**: Governance and compliance audit trail of all containment and mitigation actions.

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.12/3.14)
- Virtual environment recommended

### 2. Installation
```powershell
# Clone or navigate to the SentinelX repository
cd SentinelX

# Activate existing virtual environment (or create a new one)
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration
Copy `.env.example` to `.env` and optionally configure API keys:
```powershell
Copy-Item .env.example .env
```
*Note: SPLASH FORGE includes automated deterministic fallbacks for all AI and alerting features, so an API key is not required to run full end-to-end demonstrations.*

### 4. Launch Application
```powershell
streamlit run app.py
```
Open **`http://localhost:8501`** in your browser.

---

## 🔬 What Makes SPLASH FORGE Different?

Most cybersecurity hackathon projects are passive visualization dashboards with disconnected AI wrappers. SPLASH FORGE is a **closed-loop analyst decision-execution-verification platform**:

1. **Deterministic Chain-of-Custody**: Incidents never reference vague summaries; every alert points to immutable SQLite foreign keys linking raw events.
2. **Reversible Containment & Closed-Loop Verification**: Containment is not a one-way black hole. Analysts can quarantine high-risk hosts with a single click, audit the action, and safely revert/unblock the host when remediation is confirmed. Furthermore, SPLASH FORGE performs **real-time post-containment telemetry verification**, actively monitoring ingestion streams to mathematically verify zero subsequent packets from quarantined hosts (`THREAT NEUTRALIZED`).
3. **One-Click Incident Forensic Dossier Export**: Instantly bundle complete incident profiles, telemetry chain-of-custody, chronological milestones, containment audit records, and AI threat analyses into structured JSON dossiers or executive-formatted Markdown briefings for SIEM archival, compliance, or external CSIRT handoff.
4. **Integrated In-Console Attack Simulator**: Presenters and analysts can inject live multi-stage attack scenarios (Brute Force, Port Scan, Suspicious Auth, Privilege Escalation, Obfuscated PowerShell, or full campaigns) directly inside the Dashboard without leaving the browser.
5. **Chronological Attack Chain / Threat Timeline**: Correlated events are automatically parsed into relative time offsets (`T+0s`, `T+12s`, ...) and classified into attack milestones (Reconnaissance, Credential Access, Execution, Privilege Escalation).
6. **Observable Threat Indicators (IOCs)**: Grounded extraction of attacker IPs, targeted identities, ports, and observation windows directly from evidence.
7. **Zero-Hallucination AI Copilot**: Powered by Google Gemini with strict guardrails—the AI is forbidden from fabricating timestamps, tools, or compromise states. If Gemini is unreachable or rate-limited, SPLASH FORGE automatically engages an equally structured deterministic rule-based engine.

---

## 🔄 Core Analyst Workflow

SPLASH FORGE enforces a strict 9-stage investigative progression:

```
[01] DETECTION ➔ [02] EVIDENCE ➔ [03] RISK SCORING ➔ [04] CONTEXT ➔ [05] MITRE MAPPING
       │
       ▼
[06] INVESTIGATION ➔ [07] RECOMMENDED RESPONSE ➔ [08] REVERSIBLE CONTAINMENT ➔ [09] FORENSIC AUDIT
```

For every incident, an analyst instantly answers the 9 critical questions:
1. **What happened?** (Factual event sequence)
2. **Why is it suspicious?** (Baseline threshold & anomaly rationale)
3. **What evidence supports it?** (Exact raw security telemetry IDs)
4. **How serious is it?** (Explainable 0–100 risk score and severity)
5. **What technique/tactic is involved?** (MITRE ATT&CK technique with link)
6. **What should I investigate?** (Prioritized 4-step investigation playbook)
7. **What should I do next?** (Prescriptive containment directives)
8. **What happened after containment?** (Verification checks & recovery guidance)
9. **Can I audit and reverse the result?** (Immutable ledger with 1-click unblock)

---

## 🧪 Testing & Validation

Run the automated verification suite:

```powershell
# 1. Compile all Python modules
python -m compileall -q app.py database detection services simulator tests

# 2. Run full pytest suite (32 unit & integration tests)
pytest -q

# 3. Run automated 4-stage validation script (compilation, tests, detection, Streamlit HTTP 200)
powershell -ExecutionPolicy Bypass -File validate.ps1
```

---

## 🎬 3-Minute Hackathon Demo Flow

1. **Minute 1: Situational Awareness & In-Console Threat Injection (Dashboard)**
   - Open SPLASH FORGE at `http://localhost:8501`.
   - Show the **Situational Briefing Bar** and **Security Posture Score** (e.g., `85/100`).
   - Expand **⚡ Threat Simulation & Live Attack Scenarios** directly on the Dashboard.
   - Click **"💥 Inject Multi-Stage Advanced Campaign"** (or run `python -m simulator.run_attack_demo` from CLI).
   - Show live telemetry ingestion in **Live Events** with real-time severity metrics.
2. **Minute 2: Detection, Chain-of-Custody & AI Copilot (Alerts & Incidents)**
   - Switch to **Security Alerts**: show multi-factor risk score enrichment (`CRITICAL 95/100`) and MITRE mapping (`T1110`, `T1046`, `T1059.001`).
   - Switch to **Incidents**: inspect the newly created high-severity incident. Show the interactive **Lifecycle Stepper** (`NEW` ➔ `CONTAINED`).
   - Expand **Chronological Attack Timeline**: demonstrate `T+0s` to `T+30s` attack progression.
   - Expand **Observable Threat Indicators (IOCs)**: show extracted adversary IPs, accounts, and targeted ports.
   - Click **"Analyze Incident with AI Copilot"**: showcase the zero-hallucination report answering *What Happened*, *Why Suspicious*, *Playbook*, and *Verification Guidance*.
3. **Minute 3: Closed-Loop Containment & Forensic Dossier Export (Response & Audit)**
   - Click **"🛡️ Isolate Host (Block IP)"**: immediately observe the **Closed-Loop Verification Status Bar** confirm `✓ CLOSED-LOOP VERIFICATION CONFIRMED: 0 post-quarantine packets (THREAT NEUTRALIZED)`.
   - Expand **📥 Incident Forensic Dossier & Compliance Export**: click **Download Forensic Dossier (JSON)** or **Download Executive Briefing (MD)** to hand off complete evidence to leadership or CSIRT.
   - Demonstrate reversibility: click **"🔓 Revert Isolation (Unblock IP)"**. The host is safely released, and incident status moves to `INVESTIGATING`.
   - Switch to **Audit Logs**: show the immutable forensic ledger documenting both `BLOCK_SOURCE_IP` and `UNBLOCK_SOURCE_IP` with exact timestamps and analyst rationale.
