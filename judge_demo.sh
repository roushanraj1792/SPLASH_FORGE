#!/usr/bin/env bash
set -euo pipefail

API_URL="${SENTINELX_DEMO_API_URL:-http://10.0.2.2:8502}"
TOKEN="${SENTINELX_INGEST_TOKEN:-}"

if [[ -z "$TOKEN" ]]; then
  echo "[ERROR] SENTINELX_INGEST_TOKEN is not set."
  echo "Set it once in this terminal, then run ./judge_demo.sh again."
  exit 1
fi

echo "============================================================"
echo " SENTINELX — AUTHORIZED JUDGE DEMO SIMULATION"
echo " Target: SentinelX ingestion API"
echo "============================================================"
echo

health="$(curl -fsS "$API_URL/health")"
echo "[1/5] API health: $health"
echo

send_event() {
  local payload="$1"
  local result
  result="$(curl -fsS -X POST "$API_URL/events" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "$payload")"
  echo "      $result"
}

echo "[2/5] Brute-force simulation: 5 failed logins"
for i in {1..5}; do
  send_event "{\"event_type\":\"LOGIN\",\"source_ip\":\"10.0.0.50\",\"username\":\"kali_demo\",\"status\":\"FAILED\",\"message\":\"Authorized SentinelX demo failed login attempt $i\"}"
  sleep 1
done
echo

echo "[3/5] Port-scan simulation: 10 unique ports"
ports=(21 22 23 25 53 80 110 135 443 445)
for port in "${ports[@]}"; do
  send_event "{\"event_type\":\"NETWORK_CONNECTION\",\"source_ip\":\"10.0.0.50\",\"username\":\"kali_demo\",\"status\":\"FAILED\",\"message\":\"Authorized SentinelX demo connection attempt to port $port\",\"port\":$port}"
  sleep 5
done
echo

echo "[4/5] Privilege + PowerShell simulation"
for i in {1..3}; do
  send_event "{\"event_type\":\"PRIVILEGE_CHANGE\",\"source_ip\":\"10.0.0.50\",\"username\":\"kali_demo\",\"status\":\"SUCCESS\",\"message\":\"Authorized SentinelX demo privilege escalation event $i\"}"
  sleep 1
done

send_event '{"event_type":"POWERSHELL","source_ip":"10.0.0.50","username":"kali_demo","status":"SUCCESS","message":"Authorized SentinelX demo PowerShell ExecutionPolicy Bypass"}'
sleep 1
send_event '{"event_type":"POWERSHELL","source_ip":"10.0.0.50","username":"kali_demo","status":"SUCCESS","message":"Authorized SentinelX demo PowerShell EncodedCommand"}'
echo

echo "[5/5] Simulation complete."
echo
echo "Open SentinelX and show:"
echo "  Events → Alerts → Incident → Evidence/Timeline"
echo "  Investigation → Recommended Response → Containment → Verification"
echo
echo "No external host was scanned or attacked."
