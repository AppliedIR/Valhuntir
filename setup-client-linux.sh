#!/usr/bin/env bash
#
# setup-client-linux.sh — AIIR LLM Client Setup for Linux
#
# Configures an LLM client to connect to AIIR. Two modes:
#   Local (on SIFT): delegates to aiir setup client
#   Remote:          pure bash — curl join, config generation, asset deployment
#
# All remote deployments target ~/aiir/ as a fixed workspace directory.
# Forensic controls (hooks, permissions, sandbox) only apply when Claude Code
# is launched from within ~/aiir/ or a subdirectory.
#
# Usage:
#   ./setup-client-linux.sh                                   # Auto-detect mode
#   ./setup-client-linux.sh --client=claude-code -y           # Local, non-interactive
#   ./setup-client-linux.sh --sift=https://IP:4508 --code=XX  # Remote mode
#   ./setup-client-linux.sh --uninstall                       # Remove AIIR workspace
#   ./setup-client-linux.sh -h                                # Help
#
set -euo pipefail

# =============================================================================
# Parse Arguments
# =============================================================================

AUTO_YES=false
CLIENT=""
EXAMINER_NAME=""
SIFT_URL=""
JOIN_CODE=""
CA_CERT=""
UNINSTALL=false

for arg in "$@"; do
    case "$arg" in
        -y|--yes)          AUTO_YES=true ;;
        --client=*)        CLIENT="${arg#*=}" ;;
        --examiner=*)      EXAMINER_NAME="${arg#*=}" ;;
        --sift=*)          SIFT_URL="${arg#*=}" ;;
        --code=*)          JOIN_CODE="${arg#*=}" ;;
        --ca-cert=*)       CA_CERT="${arg#*=}" ;;
        --uninstall)       UNINSTALL=true ;;
        -h|--help)
            echo "Usage: setup-client-linux.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --client=CLIENT    LLM client (claude-code, claude-desktop, librechat, other)"
            echo "  --examiner=NAME    Examiner identity"
            echo "  --sift=URL         Gateway URL (forces remote mode)"
            echo "  --code=CODE        Join code (remote mode)"
            echo "  --ca-cert=PATH     CA certificate for TLS verification"
            echo "  --uninstall        Remove AIIR workspace and forensic controls"
            echo "  -y, --yes          Accept all defaults (non-interactive)"
            echo "  -h, --help         Show this help"
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

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()   { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()     { echo -e "${GREEN}[OK]${NC} $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()    { echo -e "${RED}[ERROR]${NC} $*"; }
header() { echo -e "\n${BOLD}=== $* ===${NC}\n"; }

prompt() {
    local msg="$1" default="${2:-}"
    if $AUTO_YES && [[ -n "$default" ]]; then
        echo "$default"
        return
    fi
    if [[ -n "$default" ]]; then
        read -rp "$(echo -e "${BOLD}$msg${NC} [$default]: ")" answer
        echo "${answer:-$default}"
    else
        read -rp "$(echo -e "${BOLD}$msg${NC}: ")" answer
        echo "$answer"
    fi
}

prompt_yn() {
    local msg="$1" default="${2:-y}"
    if $AUTO_YES; then
        [[ "$default" == "y" ]]
        return
    fi
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
echo -e "${BOLD}  AIIR — LLM Client Setup (Linux)${NC}"
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
# Mode Detection
# =============================================================================

if [[ -n "$SIFT_URL" ]]; then
    # Explicit remote mode
    LOCAL_MODE=false
elif [[ -f "$HOME/.aiir/gateway.yaml" ]] && grep -q "api_keys:" "$HOME/.aiir/gateway.yaml" 2>/dev/null; then
    LOCAL_MODE=true
else
    LOCAL_MODE=false
fi

# =============================================================================
# LOCAL MODE — delegate to aiir setup client
# =============================================================================

if $LOCAL_MODE; then
    info "SIFT platform detected (gateway.yaml found). Using local mode."

    AIIR_CMD="$HOME/.aiir/venv/bin/aiir"
    if [[ ! -x "$AIIR_CMD" ]]; then
        # Try PATH
        AIIR_CMD=$(command -v aiir 2>/dev/null || true)
    fi
    if [[ -z "$AIIR_CMD" ]]; then
        err "aiir CLI not found. Run setup-sift.sh first."
        exit 1
    fi

    ARGS=()
    [[ -n "$CLIENT" ]] && ARGS+=(--client="$CLIENT")
    $AUTO_YES && ARGS+=(-y)

    exec "$AIIR_CMD" setup client "${ARGS[@]}"
    # exec replaces process — nothing below runs in local mode
fi

# =============================================================================
# REMOTE MODE — pure bash, no Python, no git, no venv
# =============================================================================

info "Remote mode — configuring LLM client to connect to SIFT gateway."

# ---- Phase 1: Prerequisites ----

if ! command -v curl &>/dev/null; then
    err "curl is required"
    exit 1
fi

# ---- Phase 2: Join ----

header "Join Gateway"

if [[ -z "$SIFT_URL" ]]; then
    SIFT_URL=$(prompt "SIFT gateway URL (e.g., https://192.168.1.100:4508)" "")
fi
if [[ -z "$SIFT_URL" ]]; then
    err "Gateway URL is required (--sift=URL)"
    exit 1
fi

# Strip trailing slash
SIFT_URL="${SIFT_URL%/}"

if [[ -z "$JOIN_CODE" ]]; then
    JOIN_CODE=$(prompt "Join code" "")
fi
if [[ -z "$JOIN_CODE" ]]; then
    err "Join code is required (--code=CODE)"
    exit 1
fi

CURL_OPTS=(-sS --max-time 30)
if [[ -n "$CA_CERT" ]]; then
    CURL_OPTS+=(--cacert "$CA_CERT")
elif [[ "$SIFT_URL" == https* ]]; then
    # Try common CA cert location, fall back to insecure for self-signed
    if [[ -f "$HOME/.aiir/tls/ca-cert.pem" ]]; then
        CURL_OPTS+=(--cacert "$HOME/.aiir/tls/ca-cert.pem")
    else
        CURL_OPTS+=(-k)
        warn "Using insecure TLS (no CA cert). Use --ca-cert for production."
    fi
fi

# Sanitize inputs for JSON interpolation
if [[ ! "$JOIN_CODE" =~ ^[A-Za-z0-9_-]+$ ]]; then
    err "Invalid join code format (alphanumeric, dash, underscore only)"
    exit 1
fi
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
HOSTNAME_VAL=$(echo "$HOSTNAME_VAL" | tr -cd 'A-Za-z0-9._-')

info "Joining gateway at $SIFT_URL..."

JOIN_RESPONSE=$(curl "${CURL_OPTS[@]}" -X POST "$SIFT_URL/api/v1/setup/join" \
    -H "Content-Type: application/json" \
    -d "{\"code\":\"$JOIN_CODE\",\"machine_type\":\"examiner\",\"hostname\":\"$HOSTNAME_VAL\"}" 2>&1) || {
    err "Failed to connect to gateway at $SIFT_URL"
    echo "  Check the URL and ensure the gateway is running."
    exit 1
}

# Parse JSON response with grep/sed (no Python dependency)
# Response format: {"status":"joined","gateway_token":"aiir_gw_...","gateway_url":"...","backends":["forensic-mcp",...]}

# Check for error response
if echo "$JOIN_RESPONSE" | grep -q '"error"'; then
    ERROR_MSG=$(echo "$JOIN_RESPONSE" | sed 's/.*"error"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
    err "Join failed: $ERROR_MSG"
    exit 1
fi

if ! echo "$JOIN_RESPONSE" | grep -q '"gateway_token"'; then
    err "Unexpected response from gateway"
    echo "  Response: $JOIN_RESPONSE"
    exit 1
fi

GATEWAY_TOKEN=$(echo "$JOIN_RESPONSE" | sed 's/.*"gateway_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
if [[ -z "$GATEWAY_TOKEN" ]] || [[ "$GATEWAY_TOKEN" == "$JOIN_RESPONSE" ]]; then
    err "Could not extract gateway token from response"
    exit 1
fi
GATEWAY_URL=$(echo "$JOIN_RESPONSE" | sed 's/.*"gateway_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

# Extract backends array — simple approach for ["a","b","c"] format
BACKENDS_RAW=$(echo "$JOIN_RESPONSE" | sed 's/.*"backends"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/')
# Convert "a","b","c" to newline-separated list
BACKENDS=$(echo "$BACKENDS_RAW" | tr ',' '\n' | sed 's/[[:space:]]*"//g')

# Use provided URL if gateway_url is empty or missing
if [[ -z "$GATEWAY_URL" ]] || [[ "$GATEWAY_URL" == "$JOIN_RESPONSE" ]]; then
    GATEWAY_URL="$SIFT_URL"
fi

ok "Joined gateway"
info "Token: ${GATEWAY_TOKEN:0:12}..."

# Store token securely
mkdir -p "$HOME/.aiir" && chmod 700 "$HOME/.aiir"
AIIR_CONFIG="$HOME/.aiir/config.yaml"
(umask 077 && cat > "$AIIR_CONFIG" <<CONF
gateway_url: "$GATEWAY_URL"
gateway_token: "$GATEWAY_TOKEN"
CONF
)
ok "Credentials saved to $AIIR_CONFIG"

# ---- Phase 3: Examiner Identity ----

header "Examiner Identity"

if [[ -z "$EXAMINER_NAME" ]]; then
    DEFAULT_EXAMINER=$(whoami | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | head -c 40)
    EXAMINER_NAME=$(prompt "Examiner identity (name slug)" "$DEFAULT_EXAMINER")
fi

EXAMINER_NAME=$(echo "$EXAMINER_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | head -c 40)
[[ -z "$EXAMINER_NAME" ]] && EXAMINER_NAME="examiner"
ok "Examiner: $EXAMINER_NAME"

echo "examiner: $EXAMINER_NAME" >> "$AIIR_CONFIG"

# Write AIIR_EXAMINER to shell profile
SHELL_RC=""
if [[ -f "$HOME/.bashrc" ]]; then SHELL_RC="$HOME/.bashrc";
elif [[ -f "$HOME/.zshrc" ]]; then SHELL_RC="$HOME/.zshrc"; fi

if [[ -n "$SHELL_RC" ]]; then
    if grep -q "AIIR_EXAMINER" "$SHELL_RC" 2>/dev/null; then
        sed -i "s/^export AIIR_EXAMINER=.*/export AIIR_EXAMINER=\"$EXAMINER_NAME\"/" "$SHELL_RC"
    else
        echo "export AIIR_EXAMINER=\"$EXAMINER_NAME\"" >> "$SHELL_RC"
    fi
fi
export AIIR_EXAMINER="$EXAMINER_NAME"

# ---- Phase 4: LLM Client Selection ----

header "LLM Client"

if [[ -z "$CLIENT" ]]; then
    echo "  1. Claude Code"
    echo "  2. Claude Desktop"
    echo "  3. LibreChat"
    echo "  4. Other"
    echo ""
    CHOICE=$(prompt "Which LLM client?" "1")
    case "$CHOICE" in
        1) CLIENT="claude-code" ;;
        2) CLIENT="claude-desktop" ;;
        3) CLIENT="librechat" ;;
        *) CLIENT="other" ;;
    esac
fi

ok "Client: $CLIENT"

# ---- Phase 5: Workspace + MCP Config Generation ----

header "AIIR Workspace"

DEPLOY_DIR="$HOME/aiir"
mkdir -p "$DEPLOY_DIR/cases"

# Build MCP server entries from backends
# Each backend gets its own endpoint: GATEWAY_URL/mcp/BACKEND_NAME

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

# Build entries for all backends
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

# Add external MCPs
MCP_ENTRIES="$MCP_ENTRIES,
$(build_mcp_entry_noauth "zeltser-ir-writing" "https://website-mcp.zeltser.com/mcp")"

MCP_ENTRIES="$MCP_ENTRIES,
$(build_mcp_entry_noauth "microsoft-learn" "https://learn.microsoft.com/api/mcp")"

MCP_JSON="{
  \"mcpServers\": {
$MCP_ENTRIES
  }
}"

# Write config to workspace
case "$CLIENT" in
    claude-code)
        CONFIG_FILE="$DEPLOY_DIR/.mcp.json"
        (umask 077 && echo "$MCP_JSON" > "$CONFIG_FILE")
        ok "Written: $CONFIG_FILE"
        ;;
    claude-desktop)
        CONFIG_DIR="$HOME/.config/claude"
        mkdir -p "$CONFIG_DIR"
        CONFIG_FILE="$CONFIG_DIR/claude_desktop_config.json"
        (umask 077 && echo "$MCP_JSON" > "$CONFIG_FILE")
        ok "Written: $CONFIG_FILE"
        ;;
    *)
        CONFIG_FILE="$DEPLOY_DIR/.mcp.json"
        (umask 077 && echo "$MCP_JSON" > "$CONFIG_FILE")
        ok "Written: $CONFIG_FILE (reference config)"
        info "Configure your LLM client using the entries in this file."
        ;;
esac

# ---- Phase 6: Claude Code Asset Deployment ----

if [[ "$CLIENT" == "claude-code" ]]; then
    header "Claude Code Forensic Controls"

    GITHUB_RAW="https://raw.githubusercontent.com/AppliedIR"
    ERRORS=0

    # Fetch the real CLAUDE.md (245+ lines with session-start check)
    info "Fetching CLAUDE.md..."
    if curl -fsSL "$GITHUB_RAW/sift-mcp/main/claude-code/CLAUDE.md" -o "$DEPLOY_DIR/CLAUDE.md" 2>/dev/null; then
        ok "CLAUDE.md"
    else
        warn "Could not fetch CLAUDE.md"
        ERRORS=$((ERRORS + 1))
    fi

    # Fetch AGENTS.md
    info "Fetching AGENTS.md..."
    if curl -fsSL "$GITHUB_RAW/sift-mcp/main/AGENTS.md" -o "$DEPLOY_DIR/AGENTS.md" 2>/dev/null; then
        ok "AGENTS.md"
    else
        warn "Could not fetch AGENTS.md"
        ERRORS=$((ERRORS + 1))
    fi

    # Fetch FORENSIC_DISCIPLINE.md
    info "Fetching FORENSIC_DISCIPLINE.md..."
    if curl -fsSL "$GITHUB_RAW/sift-mcp/main/claude-code/FORENSIC_DISCIPLINE.md" -o "$DEPLOY_DIR/FORENSIC_DISCIPLINE.md" 2>/dev/null; then
        ok "FORENSIC_DISCIPLINE.md"
    else
        warn "Could not fetch FORENSIC_DISCIPLINE.md"
        ERRORS=$((ERRORS + 1))
    fi

    # Fetch TOOL_REFERENCE.md
    info "Fetching TOOL_REFERENCE.md..."
    if curl -fsSL "$GITHUB_RAW/sift-mcp/main/claude-code/TOOL_REFERENCE.md" -o "$DEPLOY_DIR/TOOL_REFERENCE.md" 2>/dev/null; then
        ok "TOOL_REFERENCE.md"
    else
        warn "Could not fetch TOOL_REFERENCE.md"
        ERRORS=$((ERRORS + 1))
    fi

    # Fetch and deploy forensic-audit.sh hook
    HOOKS_DIR="$DEPLOY_DIR/.claude/hooks"
    mkdir -p "$HOOKS_DIR"
    info "Fetching forensic-audit.sh..."
    if curl -fsSL "$GITHUB_RAW/sift-mcp/main/claude-code/hooks/forensic-audit.sh" -o "$HOOKS_DIR/forensic-audit.sh" 2>/dev/null; then
        chmod 755 "$HOOKS_DIR/forensic-audit.sh"
        ok "forensic-audit.sh"
    else
        warn "Could not fetch forensic-audit.sh"
        ERRORS=$((ERRORS + 1))
    fi

    info "Fetching pre-bash-guard.sh..."
    if curl -fsSL "$GITHUB_RAW/sift-mcp/main/claude-code/hooks/pre-bash-guard.sh" -o "$HOOKS_DIR/pre-bash-guard.sh" 2>/dev/null; then
        chmod 755 "$HOOKS_DIR/pre-bash-guard.sh"
        ok "pre-bash-guard.sh"
    else
        warn "Could not fetch pre-bash-guard.sh"
        ERRORS=$((ERRORS + 1))
    fi

    # Generate settings.json with all 4 blocks
    SETTINGS_DIR="$DEPLOY_DIR/.claude"
    mkdir -p "$SETTINGS_DIR"
    SETTINGS_FILE="$SETTINGS_DIR/settings.json"

    # Unquoted delimiter: $DEPLOY_DIR expands at write time to absolute path.
    # WARNING: If you add $ variables to the rules text below, they will be
    # expanded by bash. The cat << 'EOF' inside the JSON string is literal text
    # and does not cause issues because it has no $ variables.
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
        # Use Python for JSON merge (available on most Linux systems)
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

# Merge hooks
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

# Merge permissions
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

# Merge sandbox
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

    echo ""
    if (( ERRORS > 0 )); then
        warn "$ERRORS asset(s) could not be fetched. Re-run or download manually."
    else
        ok "Claude Code forensic controls deployed"
    fi
fi

# ---- Phase 7: Summary ----

header "Setup Complete"

echo "Gateway:     $GATEWAY_URL"
echo "Examiner:    $EXAMINER_NAME"
echo "Client:      $CLIENT"
echo "Workspace:   $DEPLOY_DIR"
if [[ -n "${CONFIG_FILE:-}" ]]; then
    echo "MCP config:  $CONFIG_FILE"
fi

echo ""
echo -e "${BOLD}SSH Access${NC}"
echo "  SSH access to SIFT is required for finding approval and rejection"
echo "  (aiir approve, aiir reject), evidence unlocking (aiir evidence"
echo "  unlock), and command execution (aiir execute). These operations"
echo "  require PIN or terminal confirmation and are not available through"
echo "  MCP. All other operations are available through MCP tools."

if [[ "$CLIENT" == "claude-code" ]]; then
    echo ""
    echo -e "${YELLOW}${BOLD}SSH Security Advisory${NC}"
    echo "  Claude Code has terminal access and can use your SSH credentials"
    echo "  to run commands directly on SIFT, bypassing MCP audit controls."
    echo "  To mitigate this, ensure your SSH authentication to SIFT requires"
    echo "  human interaction per use:"
    echo "    - Password-only auth (no agent-forwarded keys)"
    echo "    - ssh-add -c (agent confirmation per use)"
    echo "    - Hardware security keys (FIDO2/U2F)"
    echo ""
    echo "  Alternatively, use an MCP-only client (Claude Desktop, LibreChat)"
    echo "  which can only interact with SIFT through audited MCP tools."

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
fi

echo ""
echo -e "${BOLD}Documentation:${NC} https://appliedir.github.io/aiir/"
echo ""
