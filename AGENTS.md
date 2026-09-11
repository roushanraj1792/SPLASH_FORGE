# SentinelX — AI Development Rules

## Mission
SentinelX is an AI-assisted Security Operations Center (SOC) platform. Preserve working security functionality while improving reliability, explainability, usability, and hackathon readiness.

## Non-negotiable rules
1. Never blindly replace `app.py`.
2. Never delete a working feature to implement a new feature.
3. Preserve all existing pages, navigation, buttons, status sections, evidence sections, and backend integrations unless the change request explicitly says otherwise.
4. Preserve database compatibility. Do not delete or reset production/demo data without explicit approval.
5. Never hard-code API keys, bot tokens, passwords, or other secrets.
6. Read secrets from `.env` / environment variables.
7. Do not expose secrets in logs, UI, screenshots, reports, commits, or test output.
8. Keep the current detection engines and their interfaces stable unless a change is required and tested.
9. Keep incident evidence traceable to the underlying security events.
10. Keep MITRE ATT&CK mappings consistent with the detection type.
11. Keep containment actions safe, auditable, and reversible where possible.
12. AI output must be treated as analyst assistance, not unquestioned truth.
13. AI recommendations must be grounded in available incident evidence. Never invent evidence.
14. Do not make destructive or irreversible security actions automatically during development/demo testing.
15. Prefer small, isolated changes over large rewrites.

## Required workflow for every change
Before coding:
- Inspect the relevant files and existing implementation.
- Identify dependencies and existing behavior.
- State which files will change and why.

After coding:
- Run Python syntax compilation.
- Run the full test suite.
- Verify Streamlit startup.
- If UI changes, manually verify every affected page.
- If database changes, verify database integrity and backward compatibility.
- Report changed files, tests run, and any remaining risk.

## Minimum validation commands
```powershell
.env\Scripts\python.exe -m py_compile app.py
.env\Scripts\python.exe -m compileall -q app.py database detection services simulator tests
.env\Scripts\python.exe -m pytest -q
```

## Architecture principle
Prefer:
UI -> application/service layer -> detection/risk/incident services -> database

AI should consume structured evidence and return explainable assistance. It must not silently bypass detection, evidence, audit, or safety controls.

## Change discipline
For every feature, use:
1. Plan
2. Inspect
3. Implement
4. Test
5. Review
6. Run
7. Demo-check
8. Commit

## Git discipline
Use a separate branch for substantial features. Make small commits with descriptive messages. Never commit `.env`, credentials, generated databases containing secrets, or local virtual environments.

## Hackathon quality bar
A feature is not considered complete until:
- it works,
- it has a clear user-facing purpose,
- it does not regress existing functionality,
- it has automated coverage where practical,
- errors are handled cleanly,
- the UI communicates state clearly,
- the README/demo story explains it.
