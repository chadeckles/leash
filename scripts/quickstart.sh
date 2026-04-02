#!/usr/bin/env bash
# ── Leash Quickstart ───────────────────────────────────────────────────────
# Gets you from zero to a working demo in one command:
#   make quickstart
#
# What it does:
#   1. Installs dependencies
#   2. Starts the Leash server (background)
#   3. Waits for it to be healthy
#   4. Registers a demo agent
#   5. Tests allow/deny decisions against built-in policies
#   6. Shows the audit trail
#   7. Opens the dashboard
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

LEASH_URL="${LEASH_URL:-http://localhost:8000}"

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}${BOLD}║            🧩 Leash Quickstart                    ║${RESET}"
    echo -e "${CYAN}${BOLD}║   Rules for AI agents. Know what they did.          ║${RESET}"
    echo -e "${CYAN}${BOLD}║   Stop what they shouldn't.                         ║${RESET}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

step() {
    echo -e "\n${BOLD}[$1/6]${RESET} $2"
}

ok() {
    echo -e "  ${GREEN}✔${RESET} $1"
}

fail() {
    echo -e "  ${RED}✘${RESET} $1"
}

info() {
    echo -e "  ${DIM}$1${RESET}"
}

# ── 0. Banner ────────────────────────────────────────────────────────────────

banner

# ── 1. Install dependencies ──────────────────────────────────────────────────

step 1 "Installing dependencies..."
pip3 install -q -r requirements.txt 2>/dev/null
ok "Dependencies installed"

# ── 2. Start server ─────────────────────────────────────────────────────────

step 2 "Starting Leash server..."

# Kill any existing Leash server on port 8000
lsof -ti:8000 2>/dev/null | xargs kill -9 2>/dev/null || true
sleep 0.5

# Clean slate (fresh DB for demo)
rm -f leash.db

uvicorn_cmd="python3 -m uvicorn"

$uvicorn_cmd app.main:app --host 0.0.0.0 --port 8000 --log-level warning &
SERVER_PID=$!

# Wait for healthy
for i in $(seq 1 20); do
    if curl -sf "$LEASH_URL/health" > /dev/null 2>&1; then
        ok "Server running at $LEASH_URL (PID $SERVER_PID)"
        break
    fi
    if [ "$i" -eq 20 ]; then
        fail "Server failed to start"
        kill $SERVER_PID 2>/dev/null || true
        exit 1
    fi
    sleep 0.5
done

# Cleanup on exit
cleanup() {
    kill $SERVER_PID 2>/dev/null || true
}
trap cleanup EXIT

# ── 3. Register a demo agent ────────────────────────────────────────────────

step 3 "Registering a demo agent..."

REGISTER_RESP=$(curl -sf -X POST "$LEASH_URL/agents" \
    -H "Content-Type: application/json" \
    -d '{"name": "demo-agent", "vendor": "quickstart", "agent_type": "demo", "tags": ["quickstart"]}')

AGENT_ID=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_id'])")
TOKEN=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

ok "Agent registered: $AGENT_ID"
info "Name: demo-agent | Type: demo | Vendor: quickstart"

# ── 4. Test authorize decisions ──────────────────────────────────────────────

step 4 "Testing policy decisions..."

authorize() {
    local action="$1"
    local extra="${2:-}"
    local payload="{\"agent_id\": \"$AGENT_ID\", \"action\": \"$action\"$extra}"
    local resp
    resp=$(curl -sf -X POST "$LEASH_URL/authorize" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$payload")
    local decision=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['decision'])")
    local reason=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['reason'])")
    if [ "$decision" = "allow" ]; then
        echo -e "  ${GREEN}✔ ALLOW${RESET}  $action"
    else
        echo -e "  ${RED}✘ DENY${RESET}   $action"
    fi
    echo -e "    ${DIM}→ $reason${RESET}"
}

echo ""
info "demo-agent matches the 'demo_agent_policy' (*demo* name pattern)"
echo ""

# These should be ALLOWED by demo_agent_policy
authorize "read_file"
authorize "summarize"
authorize "write_file"

# This should be DENIED by demo_agent_policy
authorize "delete_file"

# This should be DENIED by default policy (no rule)
authorize "send_email"

# ── 5. Show audit trail ─────────────────────────────────────────────────────

step 5 "Checking the audit trail..."

AUDIT=$(curl -sf "$LEASH_URL/audit?agent_id=$AGENT_ID&limit=10")
TOTAL=$(echo "$AUDIT" | python3 -c "import sys,json; print(json.load(sys.stdin)['total'])")

ok "$TOTAL audit entries recorded (hash-chained and signed)"
info "Every decision above was automatically logged with a cryptographic signature."

# ── 6. Summary ───────────────────────────────────────────────────────────────

step 6 "You're up and running!"

echo ""
echo -e "${BOLD}  What just happened:${RESET}"
echo -e "  • Leash evaluated each action against YAML policies in ${CYAN}app/policies/${RESET}"
echo -e "  • demo_agent_policy matched because the agent name contains 'demo'"
echo -e "  • read_file, summarize, write_file → ${GREEN}allowed${RESET}"
echo -e "  • delete_file → ${RED}denied${RESET} (explicit deny rule)"
echo -e "  • send_email → ${RED}denied${RESET} (no matching rule → default deny)"
echo -e "  • Every decision was signed and hash-chained in the audit log"
echo ""
echo -e "${BOLD}  Next steps:${RESET}"
echo -e "  ${CYAN}1.${RESET} Open the dashboard    → ${BOLD}$LEASH_URL/dashboard${RESET}"
echo -e "  ${CYAN}2.${RESET} Explore the API docs  → ${BOLD}$LEASH_URL/docs${RESET}"
echo -e "  ${CYAN}3.${RESET} Edit a policy          → ${BOLD}app/policies/demo_agent.yaml${RESET}"
echo -e "  ${CYAN}4.${RESET} Try the CLI            → ${BOLD}leash agents list${RESET}"
echo -e "  ${CYAN}5.${RESET} Write your own policy  → ${BOLD}cp app/policies/email_agent.yaml app/policies/my_agent.yaml${RESET}"
echo ""
echo -e "${DIM}  Server is running in the background (PID $SERVER_PID).${RESET}"
echo -e "${DIM}  Press Ctrl+C to stop, or run: kill $SERVER_PID${RESET}"
echo ""

# Keep server running so user can explore
wait $SERVER_PID 2>/dev/null || true
