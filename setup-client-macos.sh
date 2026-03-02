#!/usr/bin/env bash
#
# setup-client-macos.sh — AIIR LLM Client Setup for macOS
#
# Joins the SIFT gateway and creates a functional ~/aiir/ workspace
# with MCP config, forensic controls, and discipline docs.
#
# Usage:
#   ./setup-client-macos.sh --sift=https://IP:4508 --code=XXXX-XXXX
#   ./setup-client-macos.sh --uninstall
#   ./setup-client-macos.sh -h
#
set -euo pipefail

# =============================================================================
# Parse Arguments
# =============================================================================

SIFT_URL=""
JOIN_CODE=""
UNINSTALL=false

for arg in "$@"; do
    case "$arg" in
        --sift=*)      SIFT_URL="${arg#*=}" ;;
        --code=*)      JOIN_CODE="${arg#*=}" ;;
        --uninstall)   UNINSTALL=true ;;
        -h|--help)
            echo "Usage: setup-client-macos.sh --sift=URL --code=CODE"
            echo ""
            echo "Options:"
            echo "  --sift=URL     Gateway URL (required)"
            echo "  --code=CODE    Join code (required)"
            echo "  --uninstall    Remove AIIR workspace"
            echo "  -h, --help     Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg (use -h for help)"
            exit 1
            ;;
    esac
done

# =============================================================================
# Colors and Helpers
# =============================================================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

info()   { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()     { echo -e "${GREEN}[OK]${NC} $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()    { echo -e "${RED}[ERROR]${NC} $*"; }
header() { echo -e "\n${BOLD}=== $* ===${NC}\n"; }

prompt_yn() {
    local msg="$1" default="${2:-y}"
    local suffix
    if [[ "$default" == "y" ]]; then suffix="[Y/n]"; else suffix="[y/N]"; fi
    read -rp "$(echo -e "${BOLD}$msg${NC} $suffix: ")" answer
    answer="${answer:-$default}"
    [[ "$(echo "$answer" | tr '[:upper:]' '[:lower:]')" == "y" ]]
}

prompt_yn_strict() {
    local msg="$1"
    while true; do
        if ! read -rp "$(echo -e "${BOLD}$msg${NC} [y/n]: ")" answer; then
            echo ""
            return 1
        fi
        case "$(echo "$answer" | tr '[:upper:]' '[:lower:]')" in
            y) return 0 ;;
            n) return 1 ;;
            *) echo "    Please enter y or n." ;;
        esac
    done
}

# =============================================================================
# Banner
# =============================================================================

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  AIIR — LLM Client Setup (macOS)${NC}"
echo -e "${BOLD}  Artificial Intelligence Incident Response${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

# =============================================================================
# Uninstall
# =============================================================================

if $UNINSTALL; then
    DEPLOY_DIR="$HOME/aiir"
    header "AIIR Forensic Controls — Uninstall"

    if [[ ! -d "$DEPLOY_DIR" ]]; then
        info "No AIIR workspace found at $DEPLOY_DIR."
        exit 0
    fi

    echo "  AIIR workspace: $DEPLOY_DIR"
    if [[ -d "$DEPLOY_DIR/cases" ]]; then
        echo ""
        echo -e "  ${YELLOW}WARNING: $DEPLOY_DIR/cases/ contains case data.${NC}"
        echo "  Back up case data before removing the workspace."
    fi
    echo ""

    if prompt_yn_strict "  Remove entire AIIR workspace ($DEPLOY_DIR)?"; then
        rm -rf "$DEPLOY_DIR"
        rm -f "$HOME/.aiir/config.yaml"
        ok "Removed $DEPLOY_DIR"
    else
        echo ""
        echo "  Removing config files only (preserving cases/)..."
        rm -rf "$DEPLOY_DIR/.claude" "$DEPLOY_DIR/.mcp.json"
        for f in CLAUDE.md AGENTS.md FORENSIC_DISCIPLINE.md TOOL_REFERENCE.md; do
            rm -f "$DEPLOY_DIR/$f"
        done
        rm -f "$HOME/.aiir/config.yaml"
        ok "Config files removed. $DEPLOY_DIR/cases/ preserved."
    fi

    echo ""
    echo "Uninstall complete."
    exit 0
fi

# =============================================================================
# Validate
# =============================================================================

if [[ -z "$SIFT_URL" ]]; then
    err "Gateway URL is required: --sift=https://IP:4508"
    exit 1
fi
if [[ -z "$JOIN_CODE" ]]; then
    err "Join code is required: --code=XXXX-XXXX"
    exit 1
fi

SIFT_URL="${SIFT_URL%/}"

# =============================================================================
# Join Gateway
# =============================================================================

info "Joining gateway at $SIFT_URL..."

CURL_OPTS=(-sS --max-time 30)
if [[ "$SIFT_URL" == https* ]]; then
    if [[ -f "$HOME/.aiir/tls/ca-cert.pem" ]]; then
        CURL_OPTS+=(--cacert "$HOME/.aiir/tls/ca-cert.pem")
    else
        CURL_OPTS+=(-k)
        warn "Using insecure TLS (no CA cert found)."
    fi
fi

# Sanitize inputs for JSON interpolation
if [[ ! "$JOIN_CODE" =~ ^[A-Za-z0-9_-]+$ ]]; then
    err "Invalid join code format (alphanumeric, dash, underscore only)"
    exit 1
fi
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
HOSTNAME_VAL=$(echo "$HOSTNAME_VAL" | tr -cd 'A-Za-z0-9._-')

JOIN_RESPONSE=$(curl "${CURL_OPTS[@]}" -X POST "$SIFT_URL/api/v1/setup/join" \
    -H "Content-Type: application/json" \
    -d "{\"code\":\"$JOIN_CODE\",\"machine_type\":\"examiner\",\"hostname\":\"$HOSTNAME_VAL\"}" 2>&1) || {
    err "Failed to connect to gateway at $SIFT_URL"
    exit 1
}

# Check for error
if echo "$JOIN_RESPONSE" | grep -q '"error"'; then
    ERROR_MSG=$(echo "$JOIN_RESPONSE" | sed 's/.*"error"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
    err "Join failed: $ERROR_MSG"
    exit 1
fi

if ! echo "$JOIN_RESPONSE" | grep -q '"gateway_token"'; then
    err "Unexpected response from gateway"
    exit 1
fi

GATEWAY_TOKEN=$(echo "$JOIN_RESPONSE" | sed 's/.*"gateway_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
if [[ -z "$GATEWAY_TOKEN" ]] || [[ "$GATEWAY_TOKEN" == "$JOIN_RESPONSE" ]]; then
    err "Could not extract gateway token from response"
    exit 1
fi
GATEWAY_URL=$(echo "$JOIN_RESPONSE" | sed 's/.*"gateway_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
BACKENDS_RAW=$(echo "$JOIN_RESPONSE" | sed 's/.*"backends"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/')
BACKENDS=$(echo "$BACKENDS_RAW" | tr ',' '\n' | sed 's/[[:space:]]*"//g')

if [[ -z "$GATEWAY_URL" ]] || [[ "$GATEWAY_URL" == "$JOIN_RESPONSE" ]]; then
    GATEWAY_URL="$SIFT_URL"
fi

ok "Joined gateway"

# Store token
mkdir -p "$HOME/.aiir" && chmod 700 "$HOME/.aiir"
(umask 077 && cat > "$HOME/.aiir/config.yaml" <<CONF
gateway_url: "$GATEWAY_URL"
gateway_token: "$GATEWAY_TOKEN"
CONF
)

# =============================================================================
# Workspace Setup
# =============================================================================

header "AIIR Workspace"

DEPLOY_DIR="$HOME/aiir"
mkdir -p "$DEPLOY_DIR/cases"
mkdir -p "$DEPLOY_DIR/.claude/hooks"

# ---- MCP Config ----

build_mcp_entry() {
    local name="$1" url="$2" token="$3"
    cat << ENTRY
    "$name": {
      "type": "streamable-http",
      "url": "$url",
      "headers": {
        "Authorization": "Bearer $token"
      }
    }
ENTRY
}

build_mcp_entry_noauth() {
    local name="$1" url="$2"
    cat << ENTRY
    "$name": {
      "type": "streamable-http",
      "url": "$url"
    }
ENTRY
}

MCP_ENTRIES=""
FIRST=true
while IFS= read -r backend; do
    [[ -z "$backend" ]] && continue
    if $FIRST; then
        FIRST=false
    else
        MCP_ENTRIES="$MCP_ENTRIES,"
    fi
    MCP_ENTRIES="$MCP_ENTRIES
$(build_mcp_entry "$backend" "$GATEWAY_URL/mcp/$backend" "$GATEWAY_TOKEN")"
done <<< "$BACKENDS"

# External MCPs
MCP_ENTRIES="$MCP_ENTRIES,
$(build_mcp_entry_noauth "zeltser-ir-writing" "https://website-mcp.zeltser.com/mcp")"
MCP_ENTRIES="$MCP_ENTRIES,
$(build_mcp_entry_noauth "microsoft-learn" "https://learn.microsoft.com/api/mcp")"

MCP_JSON="{
  \"mcpServers\": {
$MCP_ENTRIES
  }
}"

(umask 077 && echo "$MCP_JSON" > "$DEPLOY_DIR/.mcp.json")
ok "Written: $DEPLOY_DIR/.mcp.json"

# ---- Settings.json ----

SETTINGS_FILE="$DEPLOY_DIR/.claude/settings.json"

# Unquoted delimiter: $DEPLOY_DIR expands at write time.
# WARNING: Do not add $ variables to the rules text — they will expand.
SETTINGS_CONTENT=$(cat << SETTINGS
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "cat << 'EOF'\n<forensic-rules>\nPLAN before 3+ steps | EVIDENCE for claims | APPROVAL before conclusions\nRECORD actions via forensic-mcp | NO DELETE without approval\n</forensic-rules>\nEOF"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$DEPLOY_DIR/.claude/hooks/pre-bash-guard.sh"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$DEPLOY_DIR/.claude/hooks/forensic-audit.sh"
          }
        ]
      }
    ]
  },
  "permissions": {
    "allow": [
      "mcp__forensic-mcp__*",
      "mcp__case-mcp__*",
      "mcp__sift-mcp__*",
      "mcp__report-mcp__*",
      "mcp__forensic-rag-mcp__*",
      "mcp__windows-triage-mcp__*",
      "mcp__opencti-mcp__*",
      "mcp__wintools-mcp__*",
      "mcp__remnux-mcp__*",
      "mcp__aiir__*",
      "mcp__zeltser-ir-writing__*",
      "mcp__microsoft-learn__*"
    ],
    "deny": [
      "Edit(**/findings.json)",
      "Edit(**/timeline.json)",
      "Edit(**/approvals.jsonl)",
      "Edit(**/todos.json)",
      "Edit(**/CASE.yaml)",
      "Edit(**/actions.jsonl)",
      "Edit(**/audit/*.jsonl)",
      "Write(**/findings.json)",
      "Write(**/timeline.json)",
      "Write(**/approvals.jsonl)",
      "Write(**/todos.json)",
      "Write(**/CASE.yaml)",
      "Write(**/actions.jsonl)",
      "Write(**/audit/*.jsonl)",
      "Edit(**/evidence.json)",
      "Write(**/evidence.json)",
      "Read(/var/lib/aiir/**)",
      "Edit(/var/lib/aiir/**)",
      "Write(/var/lib/aiir/**)",
      "Bash(aiir approve*)",
      "Bash(aiir reject*)",
      "Edit(**/.claude/settings.json)",
      "Write(**/.claude/settings.json)",
      "Edit(**/.claude/CLAUDE.md)",
      "Write(**/.claude/CLAUDE.md)",
      "Edit(**/.claude/rules/**)",
      "Write(**/.claude/rules/**)",
      "Edit(**/.aiir/hooks/**)",
      "Write(**/.aiir/hooks/**)",
      "Edit(**/.aiir/active_case)",
      "Write(**/.aiir/active_case)",
      "Edit(**/.aiir/gateway.yaml)",
      "Write(**/.aiir/gateway.yaml)",
      "Edit(**/pending-reviews.json)",
      "Write(**/pending-reviews.json)"
    ]
  },
  "sandbox": {
    "enabled": true,
    "allowUnsandboxedCommands": false
  }
}
SETTINGS
)

if [[ -f "$SETTINGS_FILE" ]] && command -v python3 &>/dev/null; then
    info "Existing settings.json found. Merging..."
    SETTINGS_FILE="$SETTINGS_FILE" SETTINGS_CONTENT="$SETTINGS_CONTENT" python3 << 'PYMERGE'
import json, sys, os

target_path = os.environ.get("SETTINGS_FILE", "")
incoming_str = os.environ.get("SETTINGS_CONTENT", "{}")

if not target_path:
    sys.exit(1)

try:
    with open(target_path) as f:
        existing = json.load(f)
except (json.JSONDecodeError, FileNotFoundError):
    existing = {}

try:
    incoming = json.loads(incoming_str)
except json.JSONDecodeError:
    sys.exit(1)

if "hooks" in incoming:
    existing_hooks = existing.setdefault("hooks", {})
    for hook_type, entries in incoming["hooks"].items():
        if hook_type not in existing_hooks:
            existing_hooks[hook_type] = entries
        else:
            existing_cmds = set()
            for entry in existing_hooks[hook_type]:
                for h in entry.get("hooks", []):
                    existing_cmds.add(h.get("command", ""))
            for entry in entries:
                new_cmds = [h.get("command", "") for h in entry.get("hooks", [])]
                if not any(c in existing_cmds for c in new_cmds):
                    existing_hooks[hook_type].append(entry)

if "permissions" in incoming:
    existing_perms = existing.setdefault("permissions", {})
    if "allow" in incoming["permissions"]:
        existing_allow = set(existing_perms.get("allow", []))
        for rule in incoming["permissions"]["allow"]:
            existing_allow.add(rule)
        existing_perms["allow"] = sorted(existing_allow)
    if "deny" in incoming["permissions"]:
        existing_deny = set(existing_perms.get("deny", []))
        # Remove old forensic rules on re-deploy
        existing_deny -= {"Bash(rm -rf *)", "Bash(mkfs*)", "Bash(dd *)"}
        for rule in incoming["permissions"]["deny"]:
            existing_deny.add(rule)
        existing_perms["deny"] = sorted(existing_deny)

if "sandbox" in incoming:
    existing.setdefault("sandbox", {}).update(incoming["sandbox"])

with open(target_path, "w") as f:
    json.dump(existing, f, indent=2)
    f.write("\n")
PYMERGE
    ok "settings.json (merged)"
elif [[ -f "$SETTINGS_FILE" ]]; then
    warn "python3 not found. Overwriting existing settings.json."
    echo "$SETTINGS_CONTENT" > "$SETTINGS_FILE"
    ok "settings.json (overwritten)"
else
    echo "$SETTINGS_CONTENT" > "$SETTINGS_FILE"
    ok "settings.json (hooks + permissions + sandbox)"
fi

# ---- Fetch assets from GitHub ----

GITHUB_RAW="https://raw.githubusercontent.com/AppliedIR"
ERRORS=0

info "Fetching CLAUDE.md..."
if curl -fsSL "$GITHUB_RAW/sift-mcp/main/claude-code/CLAUDE.md" -o "$DEPLOY_DIR/CLAUDE.md" 2>/dev/null; then
    ok "CLAUDE.md"
else
    warn "Could not fetch CLAUDE.md"
    ERRORS=$((ERRORS + 1))
fi

info "Fetching AGENTS.md..."
if curl -fsSL "$GITHUB_RAW/sift-mcp/main/AGENTS.md" -o "$DEPLOY_DIR/AGENTS.md" 2>/dev/null; then
    ok "AGENTS.md"
else
    warn "Could not fetch AGENTS.md"
    ERRORS=$((ERRORS + 1))
fi

info "Fetching FORENSIC_DISCIPLINE.md..."
if curl -fsSL "$GITHUB_RAW/sift-mcp/main/claude-code/FORENSIC_DISCIPLINE.md" -o "$DEPLOY_DIR/FORENSIC_DISCIPLINE.md" 2>/dev/null; then
    ok "FORENSIC_DISCIPLINE.md"
else
    warn "Could not fetch FORENSIC_DISCIPLINE.md"
    ERRORS=$((ERRORS + 1))
fi

info "Fetching TOOL_REFERENCE.md..."
if curl -fsSL "$GITHUB_RAW/sift-mcp/main/claude-code/TOOL_REFERENCE.md" -o "$DEPLOY_DIR/TOOL_REFERENCE.md" 2>/dev/null; then
    ok "TOOL_REFERENCE.md"
else
    warn "Could not fetch TOOL_REFERENCE.md"
    ERRORS=$((ERRORS + 1))
fi

info "Fetching forensic-audit.sh..."
if curl -fsSL "$GITHUB_RAW/sift-mcp/main/claude-code/hooks/forensic-audit.sh" -o "$DEPLOY_DIR/.claude/hooks/forensic-audit.sh" 2>/dev/null; then
    chmod 755 "$DEPLOY_DIR/.claude/hooks/forensic-audit.sh"
    ok "forensic-audit.sh"
else
    warn "Could not fetch forensic-audit.sh"
    ERRORS=$((ERRORS + 1))
fi

info "Fetching pre-bash-guard.sh..."
if curl -fsSL "$GITHUB_RAW/sift-mcp/main/claude-code/hooks/pre-bash-guard.sh" -o "$DEPLOY_DIR/.claude/hooks/pre-bash-guard.sh" 2>/dev/null; then
    chmod 755 "$DEPLOY_DIR/.claude/hooks/pre-bash-guard.sh"
    ok "pre-bash-guard.sh"
else
    warn "Could not fetch pre-bash-guard.sh"
    ERRORS=$((ERRORS + 1))
fi

if (( ERRORS > 0 )); then
    warn "$ERRORS asset(s) could not be fetched. Re-run or download manually."
fi

# =============================================================================
# Summary
# =============================================================================

header "Setup Complete"

echo "Gateway:     $GATEWAY_URL"
echo "Workspace:   $DEPLOY_DIR"

echo ""
echo -e "${BOLD}SSH Access${NC}"
echo "  SSH access to SIFT is required for finding approval and rejection"
echo "  (aiir approve, aiir reject), evidence unlocking (aiir evidence"
echo "  unlock), and command execution (aiir execute). These operations"
echo "  require PIN or terminal confirmation and are not available through"
echo "  MCP. All other operations are available through MCP tools."

echo ""
echo -e "${YELLOW}${BOLD}IMPORTANT: Terminal-Access LLM Clients${NC}"
echo "  If you use Claude Code or another LLM client with terminal access,"
echo "  the LLM can use your SSH credentials to run commands directly on"
echo "  SIFT, bypassing MCP audit controls and forensic integrity features."
echo "  We recommend MCP-only clients (Claude Desktop, LibreChat) which can"
echo "  only interact with SIFT through audited MCP tools."
echo ""
echo "  If you choose to use a terminal-access LLM, ensure your SSH"
echo "  authentication to SIFT requires human interaction per use (password"
echo "  auth, ssh-add -c, or hardware security keys) so the LLM cannot"
echo "  authenticate automatically."

echo ""
echo -e "${BOLD}AIIR workspace created at ~/aiir/${NC}"
echo ""
echo -e "${YELLOW}${BOLD}IMPORTANT:${NC} Always launch Claude Code from ~/aiir/ or a subdirectory."
echo "Forensic controls (audit logging, guardrails, MCP tools) only apply"
echo "when Claude Code is started from within this directory."
echo ""
echo "  cd ~/aiir && claude"
echo ""
echo "To organize case work while maintaining controls:"
echo ""
echo "  mkdir ~/aiir/cases/INC-2026-001"
echo "  cd ~/aiir/cases/INC-2026-001 && claude"

echo ""
echo -e "${BOLD}Documentation:${NC} https://appliedir.github.io/aiir/"
echo ""
