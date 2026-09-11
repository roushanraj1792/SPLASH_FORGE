# SentinelX — Autonomous Security Operations Center (Mini-SIEM)

> **Enterprise AI-Assisted Threat Detection, Incident Orchestration & Containment Platform**

SentinelX is an autonomous Security Operations Center (SOC) and mini-SIEM platform engineered for real-time threat telemetry ingestion, deterministic rule correlation, explainable multi-factor risk scoring, automated host containment, and evidence-grounded AI copilot analysis.

---

## 🛡️ Core Architecture

SentinelX processes host and network telemetry through a 9-stage pipeline:

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

SentinelX provides 6 dedicated operational consoles:

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
*Note: SentinelX includes automated rule-based fallbacks for all AI and alerting features, so an API key is not required to run full end-to-end demonstrations.*

### 4. Launch Application
```powershell
streamlit run app.py
```
Open **`http://localhost:8501`** in your browser.

---

## 🧪 Testing & Validation

Run the automated verification suite:

```powershell
# Compile all modules
python -m compileall -q app.py database detection services simulator tests

# Run full pytest suite
pytest -q

# Run automated validation script
powershell -ExecutionPolicy Bypass -File validate.ps1
```

---

## 🎯 Live Attack Simulation

Demonstrate autonomous detection and containment:

```powershell
# Run the interactive multi-attack simulator
python -m simulator.run_attack_demo
```
