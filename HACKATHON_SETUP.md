# SPLASH FORGE — Hackathon Setup & Upgrade Plan

## Goal
Build SPLASH FORGE into a stable, demo-ready AI-assisted SOC platform while keeping one controlled application source of truth.

## Phase 0 — Freeze and baseline
1. Keep the current `app.py`.
2. Keep the existing backup.
3. Keep the UI/UX master file separately until integration is validated.
4. Run syntax + tests before major changes.
5. Initialize Git and create a baseline commit.

## Phase 1 — AI development environment
1. Open the SentinelX root folder in Google Antigravity.
2. Add `AGENTS.md` to the project root.
3. Tell the coding agent to read `AGENTS.md` before modifying anything.
4. Use Gemini for product AI/SOC intelligence through the existing service layer.
5. Do not give the coding agent permission to overwrite the whole project without review.

## Phase 2 — Architecture audit
Review:
- `app.py`
- `database/`
- `detection/`
- `services/`
- `simulator/`
- `tests/`
- `.env.example`
- `pytest.ini`

Produce a feature matrix showing:
- feature
- implementation file
- UI location
- test coverage
- dependencies
- risk of regression

## Phase 3 — Safe UI/backend integration
Use the recovered UI/UX master as a reference. Compare it with the current `app.py` before merging. Do not blindly replace `app.py`.

Preserve:
- Dashboard
- Live Events
- Security Alerts
- Incidents
- MITRE ATT&CK
- Audit Logs
- detection/risk engines
- incident evidence
- AI SOC Copilot
- containment
- audit trail

## Phase 4 — Hackathon upgrades
Priority order:
1. Reliability and error handling
2. Evidence-grounded Gemini investigation
3. Alert correlation
4. Threat timeline / attack chain
5. IOC extraction and enrichment
6. Explainable risk scoring
7. Analyst recommendations
8. Incident report export
9. Demo/attack simulation mode
10. Performance and UI polish
11. Documentation and architecture diagram

## Phase 5 — Final validation
Run:
- py_compile
- compileall
- pytest
- Streamlit startup
- manual UI walkthrough
- Gemini test
- Telegram test if configured
- containment safety test
- clean demo scenario

## Final demo story
Telemetry -> Detection -> Risk -> Incident -> Evidence -> MITRE -> Gemini Investigation -> Recommended Response -> Safe Containment -> Audit

## Golden rule
Every future upgrade must be additive, tested, reviewable, and reversible.
