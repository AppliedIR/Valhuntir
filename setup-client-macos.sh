#!/usr/bin/env bash
#
# setup-client-macos.sh — Valhuntir LLM Client Setup for macOS
#
# Joins the SIFT gateway and creates a functional ~/vhir/ workspace
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
EXAMINER_NAME=""
UNINSTALL=false

for arg in "$@"; do
    case "$arg" in
        --sift=*)      SIFT_URL="${arg#*=}" ;;
        --code=*)      JOIN_CODE="${arg#*=}" ;;
        --examiner=*)  EXAMINER_NAME="${arg#*=}" ;;
        --uninstall)   UNINSTALL=true ;;
        -h|--help)
            echo "Usage: setup-client-macos.sh --sift=URL --code=CODE"
            echo ""
            echo "Options:"
            echo "  --sift=URL         Gateway URL (required)"
            echo "  --code=CODE        Join code (required)"
            echo "  --examiner=NAME    Examiner identity"
            echo "  --uninstall        Remove Valhuntir workspace"
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

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

info()   { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()     { echo -e "${GREEN}[OK]${NC} $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $*"; }

# A user's file is backed up (mode kept) before it's changed or removed, with
# the command that puts it back.
backup_file() {
    local f="$1" base bak n=1
    base="$f.vhir-backup-$(date -u +%Y%m%dT%H%M%SZ)"
    bak="$base"
    while [[ -e "$bak" ]]; do n=$((n + 1)); bak="$base-$n"; done
    cp -p "$f" "$bak"
    warn "Backed up $f -> $bak"
    printf '    To undo: cp -p %q %q\n' "$bak" "$f"
}
# Move a new version ($1) over a file ($2), backing the file up if that changes it.
replace_file() {
    if [[ -f "$2" ]] && ! cmp -s "$1" "$2"; then backup_file "$2"; fi
    cat "$1" > "$2"
    rm -f "$1"
}
err()    { echo -e "${RED}[ERROR]${NC} $*"; }
header() { echo -e "\n${BOLD}=== $* ===${NC}\n"; }

# Fetch every skill file skills/MANIFEST lists into $1. Each file is fetched and
# replaced: an edit to a vhir skill is lost on re-run. Counts failures in ERRORS.
fetch_skills() {
    local dest="$1" manifest rel fetched=0
    info "Fetching skills..."
    if ! manifest=$(curl -fsSL "$GITHUB_RAW/sift-mcp/main/skills/MANIFEST" 2>/dev/null); then
        warn "Could not fetch the skills list"
        ERRORS=$((ERRORS + 1))
        return 0
    fi
    while IFS= read -r rel; do
        case "$rel" in
            "" | \#*) continue ;;
            /* | *..* | *[!A-Za-z0-9._/-]*)
                warn "Skipped an unexpected skills path: $rel"
                ERRORS=$((ERRORS + 1))
                continue
                ;;
        esac
        mkdir -p "$(dirname "$dest/$rel")"
        if curl -fsSL "$GITHUB_RAW/sift-mcp/main/skills/$rel" -o "$dest/$rel" 2>/dev/null; then
            fetched=$((fetched + 1))
        else
            warn "Could not fetch skills/$rel"
            ERRORS=$((ERRORS + 1))
        fi
    done <<< "$manifest"
    ok "$fetched skill files"
}


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

prompt() {
    local msg="$1" default="$2" reply
    printf "  %s [%s]: " "$msg" "$default" >&2
    read -r reply
    echo "${reply:-$default}"
}

# =============================================================================
# Banner
# =============================================================================

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  Valhuntir — LLM Client Setup (macOS)${NC}"
echo -e "${BOLD}  AI-Assisted Forensic Investigation${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

# =============================================================================
# Uninstall
# =============================================================================

if $UNINSTALL; then
    DEPLOY_DIR="$HOME/vhir"
    header "Valhuntir Forensic Controls — Uninstall"

    # Codex: Valhuntir's profile, skills and agent (never ~/.codex/config.toml)
    CODEX_FILES=()
    for f in "$HOME/.codex/valhuntir.config.toml" "$HOME/.codex/agents/finding-skeptic.toml"; do
        [[ -f "$f" ]] && CODEX_FILES+=("$f")
    done
    for d in "$HOME/.agents/skills"/vhir-* "$HOME/.agents/skills/finding-skeptic"; do
        [[ -d "$d" ]] && CODEX_FILES+=("$d")
    done
    if (( ${#CODEX_FILES[@]} > 0 )); then
        echo "  Codex files:"
        printf '    %s\n' "${CODEX_FILES[@]}"
        if prompt_yn_strict "  Remove Valhuntir's Codex profile, skills and agent?"; then
            rm -rf "${CODEX_FILES[@]}"
            ok "Removed Valhuntir's Codex files"
        fi
        echo ""
    fi


    if [[ ! -d "$DEPLOY_DIR" ]]; then
        info "No Valhuntir workspace found at $DEPLOY_DIR."
        exit 0
    fi

    echo "  Valhuntir workspace: $DEPLOY_DIR"
    if [[ -d "$DEPLOY_DIR/cases" ]]; then
        echo ""
        echo -e "  ${YELLOW}WARNING: $DEPLOY_DIR/cases/ contains case data.${NC}"
        echo "  Back up case data before removing the workspace."
    fi
    echo ""

    if prompt_yn_strict "  Remove entire Valhuntir workspace ($DEPLOY_DIR)?"; then
        rm -rf "$DEPLOY_DIR"
        rm -f "$HOME/.vhir/config.yaml"
        ok "Removed $DEPLOY_DIR"
    else
        echo ""
        echo "  Removing config files only (preserving cases/)..."
        rm -rf "$DEPLOY_DIR/.claude" "$DEPLOY_DIR/.mcp.json"
        for f in CLAUDE.md AGENTS.md FORENSIC_DISCIPLINE.md TOOL_REFERENCE.md; do
            rm -f "$DEPLOY_DIR/$f"
        done
        rm -f "$HOME/.vhir/config.yaml"
        ok "Config files removed. $DEPLOY_DIR/cases/ preserved."
    fi

    # Clean shell profile (Valhuntir_EXAMINER + marker)
    SHELL_RC=""
    if [[ -f "$HOME/.bashrc" ]]; then SHELL_RC="$HOME/.bashrc";
    elif [[ -f "$HOME/.zshrc" ]]; then SHELL_RC="$HOME/.zshrc"; fi

    if [[ -n "$SHELL_RC" ]] && grep -q "Valhuntir" "$SHELL_RC" 2>/dev/null; then
        sed -i '' '/# Valhuntir Platform/d' "$SHELL_RC"
        sed -i '' '/Valhuntir_EXAMINER/d' "$SHELL_RC"
        sed -i '' '/# vhir-path/d' "$SHELL_RC"
        sed -i '' '/register-python-argcomplete vhir/d' "$SHELL_RC"
        ok "Removed Valhuntir lines from $SHELL_RC"
    fi

    # Remove empty ~/.vhir/ directory
    rmdir "$HOME/.vhir" 2>/dev/null || true

    # Claude Desktop config
    CLAUDE_DESKTOP_CFG="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
    if [[ -f "$CLAUDE_DESKTOP_CFG" ]]; then
        echo ""
        echo "  Claude Desktop config: $CLAUDE_DESKTOP_CFG"
        if prompt_yn_strict "  Remove Claude Desktop config?"; then
            backup_file "$CLAUDE_DESKTOP_CFG"
            rm -f "$CLAUDE_DESKTOP_CFG"
            ok "Removed $CLAUDE_DESKTOP_CFG"
        fi
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
    if [[ -f "$HOME/.vhir/tls/ca-cert.pem" ]]; then
        CURL_OPTS+=(--cacert "$HOME/.vhir/tls/ca-cert.pem")
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
mkdir -p "$HOME/.vhir" && chmod 700 "$HOME/.vhir"
(umask 077 && cat > "$HOME/.vhir/config.yaml" <<CONF
gateway_url: "$GATEWAY_URL"
gateway_token: "$GATEWAY_TOKEN"
CONF
)

# ---- Examiner Identity ----

header "Examiner Identity"

if [[ -z "$EXAMINER_NAME" ]]; then
    DEFAULT_EXAMINER=$(whoami | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | head -c 20)
    EXAMINER_NAME=$(prompt "Examiner identity (name slug)" "$DEFAULT_EXAMINER")
fi

EXAMINER_NAME=$(echo "$EXAMINER_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | head -c 20)
[[ -z "$EXAMINER_NAME" ]] && EXAMINER_NAME="examiner"
ok "Examiner: $EXAMINER_NAME"

echo "examiner: $EXAMINER_NAME" >> "$HOME/.vhir/config.yaml"

# Write VHIR_EXAMINER to shell profile
SHELL_RC=""
if [[ -f "$HOME/.zshrc" ]]; then SHELL_RC="$HOME/.zshrc";
elif [[ -f "$HOME/.bashrc" ]]; then SHELL_RC="$HOME/.bashrc"; fi

if [[ -n "$SHELL_RC" ]]; then
    # Clean up old naming from prior installs
    sed -i '' '/^export Valhuntir_EXAMINER=/d' "$SHELL_RC" 2>/dev/null || true
    if grep -q '^export VHIR_EXAMINER=' "$SHELL_RC" 2>/dev/null; then
        sed -i '' "s/^export VHIR_EXAMINER=.*/export VHIR_EXAMINER=\"$EXAMINER_NAME\"/" "$SHELL_RC"
    else
        [[ -s "$SHELL_RC" && -n "$(tail -c1 "$SHELL_RC")" ]] && echo >> "$SHELL_RC"
        echo "export VHIR_EXAMINER=\"$EXAMINER_NAME\"" >> "$SHELL_RC"
    fi
fi
export VHIR_EXAMINER="$EXAMINER_NAME"

# =============================================================================
# Workspace Setup
# =============================================================================

header "Valhuntir Workspace"

DEPLOY_DIR="$HOME/vhir"
mkdir -p "$DEPLOY_DIR/cases"

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

# ---- Client Choice ----

echo ""
echo "  Which LLM client?"
echo "  1. Claude Code"
echo "  2. Codex"
echo "  3. LibreChat"
echo "  4. Other"
echo ""
echo "  (Claude Desktop isn't offered: its commands aren't audited. Use Claude Code"
echo "  on the SIFT workstation, or Claude Code or Codex here.)"
echo ""
CHOICE=$(prompt "Choose" "1")
case "$CHOICE" in
    1) CLIENT="claude-code" ;;
    2) CLIENT="codex" ;;
    3) CLIENT="librechat" ;;
    *) CLIENT="other" ;;
esac

# ---- Write client-specific config ----

case "$CLIENT" in
    claude-code)
        CONFIG_FILE="$DEPLOY_DIR/.mcp.json"
        (umask 077 && echo "$MCP_JSON" > "$CONFIG_FILE.vhir-new" &&
            replace_file "$CONFIG_FILE.vhir-new" "$CONFIG_FILE")
        ok "Written: $CONFIG_FILE"
        ;;
    codex)
        ;;  # Valhuntir's Codex profile, below
    librechat)
        CONFIG_FILE="$DEPLOY_DIR/librechat_mcp.yaml"
        (umask 077 && echo "$MCP_JSON" > "$CONFIG_FILE")
        ok "Written: $CONFIG_FILE (merge into librechat.yaml)"
        ;;
    *)
        CONFIG_FILE="$DEPLOY_DIR/vhir-mcp-config.json"
        (umask 077 && echo "$MCP_JSON" > "$CONFIG_FILE")
        ok "Written: $CONFIG_FILE (reference config)"
        info "Configure your LLM client using the entries in this file."
        ;;
esac

# ---- Codex: Valhuntir's profile, the skills and the skeptic's agent ----
# The profile is ~/.codex/valhuntir.config.toml (codex -p valhuntir); the
# user's ~/.codex/config.toml is never written.

if [[ "$CLIENT" == "codex" ]]; then
    header "Codex"
    GITHUB_RAW="https://raw.githubusercontent.com/AppliedIR"
    ERRORS=0
    PROFILE="$HOME/.codex/valhuntir.config.toml"
    mkdir -p "$HOME/.codex/agents" "$HOME/.agents/skills"
    fetch_skills "$HOME/.agents/skills"
    if curl -fsSL "$GITHUB_RAW/sift-mcp/main/agents/finding-skeptic/codex.toml" -o "$HOME/.codex/agents/finding-skeptic.toml" 2>/dev/null; then
        ok "finding-skeptic agent"
    else
        warn "Could not fetch the finding-skeptic agent"
        ERRORS=$((ERRORS + 1))
    fi
    PARTS=$(mktemp -d)
    INSTRUCTIONS=""
    NL=$'\n'
    for part in AGENTS.md claude-code/full/FORENSIC_DISCIPLINE.md codex/OVERLAY.md codex/REMOTE.md; do
        if curl -fsSL "$GITHUB_RAW/sift-mcp/main/$part" -o "$PARTS/part" 2>/dev/null; then
            # each part without its trailing newlines, joined by a blank line
            [[ -n "$INSTRUCTIONS" ]] && INSTRUCTIONS+="$NL$NL"
            INSTRUCTIONS+="$(cat "$PARTS/part")"
        else
            warn "Could not fetch $part"
            INSTRUCTIONS=""
            ERRORS=$((ERRORS + 1))
            break
        fi
    done
    rm -rf "$PARTS"
    if [[ -z "$INSTRUCTIONS" ]] || [[ "$INSTRUCTIONS" == *"'''"* ]]; then
        warn "Valhuntir's instructions for Codex couldn't be fetched; $PROFILE not written."
    else
        (
            umask 077
            {
                echo "# Valhuntir's Codex profile, for: codex -p valhuntir"
                echo "# vhir's client setup writes this file. It holds the"
                echo "# gateway token, so only you can read it."
                echo 'sandbox_mode = "workspace-write"'
                echo 'approval_policy = "on-request"'
                echo 'project_doc_max_bytes = 0'
                printf "developer_instructions = '''\n%s\n'''\n" "$INSTRUCTIONS"
                while IFS= read -r backend; do
                    [[ "$backend" =~ ^[A-Za-z0-9_-]+$ ]] || continue
                    printf '\n[mcp_servers.%s]\nurl = "%s"\n' "$backend" "$GATEWAY_URL/mcp/$backend"
                    printf 'http_headers = { Authorization = "Bearer %s" }\n' "$GATEWAY_TOKEN"
                    printf 'default_tools_approval_mode = "approve"\n'
                done <<< "$BACKENDS"
                printf '\n[mcp_servers.zeltser-ir-writing]\nurl = "https://website-mcp.zeltser.com/mcp"\n'
                printf '\n[mcp_servers.microsoft-learn]\nurl = "https://learn.microsoft.com/api/mcp"\n'
            } > "$PROFILE.vhir-new"
        )
        if [[ -f "$PROFILE" ]] && ! cmp -s "$PROFILE.vhir-new" "$PROFILE"; then
            echo "  Changes to $PROFILE:"
            { diff -u "$PROFILE" "$PROFILE.vhir-new" || true; } | sed -E 's/(vhir_[a-z]{2}_)[0-9A-Za-z]+/\1…/g; s/^/    /'
        fi
        replace_file "$PROFILE.vhir-new" "$PROFILE"
        chmod 600 "$PROFILE"
        ok "Written: $PROFILE"
    fi
    if [[ -f "$HOME/.codex/config.toml" ]] && grep -Eq '^[[:space:]]*sandbox_mode[[:space:]]*=[[:space:]]*"danger-full-access"' "$HOME/.codex/config.toml"; then
        warn "$HOME/.codex/config.toml sets sandbox_mode = \"danger-full-access\": that widens Codex's sandbox. vhir doesn't edit that file."
    fi
    if (( ERRORS > 0 )); then
        warn "$ERRORS Codex file(s) could not be fetched. Re-run, or fetch them by hand."
    fi
fi

# ---- Claude Code assets (skip for other clients) ----

if [[ "$CLIENT" == "claude-code" ]]; then

mkdir -p "$DEPLOY_DIR/.claude/hooks"

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
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$DEPLOY_DIR/.claude/hooks/forensic-audit.sh"
          }
        ]
      },
      {
        "matcher": "Skill",
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
      "mcp__threatintel-mcp__*",
      "mcp__wintools-mcp__*",
      "mcp__remnux-mcp__*",
      "mcp__vhir__*",
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
      "Edit(**/evidence.json)",
      "Edit(**/evidence-verified.json)",
      "Read(//var/lib/vhir/**)",
      "Edit(//var/lib/vhir/**)",
      "Bash(vhir approve*)",
      "Bash(*vhir approve*)",
      "Bash(vhir reject*)",
      "Bash(*vhir reject*)",
      "Edit(**/.claude/settings.json)",
      "Edit(**/.claude/CLAUDE.md)",
      "Edit(**/.claude/rules/**)",
      "Edit(**/.vhir/hooks/**)",
      "Edit(**/.vhir/active_case)",
      "Edit(**/.vhir/gateway.yaml)",
      "Edit(**/.vhir/config.yaml)",
      "Edit(**/.vhir/.password_lockout)",
      "Edit(**/pending-reviews.json)",
      "Edit(**/.claude/skills/**)",
      "Edit(**/.claude/agents/**)",
      "Edit(**/host-observations.jsonl)",
      "Edit(**/host-decisions.jsonl)",
      "Edit(**/host-ops.json)",
      "Edit(**/host-dictionary.yaml)",
      "Edit(**/.vhir/case-paths.json)"
    ]
  },
  "sandbox": {
    "enabled": true,
    "allowUnsandboxedCommands": false,
    "filesystem": {
      "denyWrite": [
        "~/.vhir/gateway.yaml",
        "~/.vhir/config.yaml",
        "~/.vhir/active_case",
        "~/.vhir/hooks",
        "~/.vhir/.password_lockout",
        "~/.vhir/.pin_lockout",
        "~/.claude/settings.json",
        "~/.claude/CLAUDE.md",
        "~/.claude/rules"
      ]
    }
  }
}
SETTINGS
)

if [[ -f "$SETTINGS_FILE" ]] && command -v python3 &>/dev/null; then
    info "Existing settings.json found. Merging..."
    MERGE_RC=0
    rm -f "$SETTINGS_FILE.vhir-new"  # only this run's merge is ever installed
    SETTINGS_FILE="$SETTINGS_FILE" SETTINGS_CONTENT="$SETTINGS_CONTENT" python3 << 'PYMERGE' || MERGE_RC=$?
import json, sys, os

target_path = os.environ.get("SETTINGS_FILE", "")
incoming_str = os.environ.get("SETTINGS_CONTENT", "{}")

if not target_path:
    sys.exit(1)
unparseable = False

try:
    with open(target_path) as f:
        existing = json.load(f)
except FileNotFoundError:
    existing = {}
except json.JSONDecodeError:  # replaced, with a backup; never reported as merged
    existing = {}
    unparseable = True

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
            # by matcher and command: one hook can serve two matchers (Bash, Skill)
            existing_keys = set()
            for entry in existing_hooks[hook_type]:
                for h in entry.get("hooks", []):
                    existing_keys.add((entry.get("matcher", ""), h.get("command", "")))
            for entry in entries:
                new_keys = [(entry.get("matcher", ""), h.get("command", "")) for h in entry.get("hooks", [])]
                if not any(k in existing_keys for k in new_keys):
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

# Merge sandbox: every list is a union with the user's own (a scalar takes
# vhir's value; the change is shown before it's written)
def _union(cur, new):
    for k, v in new.items():
        if isinstance(v, dict) and isinstance(cur.get(k), dict):
            _union(cur[k], v)
        elif isinstance(v, list) and isinstance(cur.get(k), list):
            cur[k] = cur[k] + [x for x in v if x not in cur[k]]
        else:
            cur[k] = v


if "sandbox" in incoming:
    _union(existing.setdefault("sandbox", {}), incoming["sandbox"])

with open(target_path + ".vhir-new", "w") as f:
    json.dump(existing, f, indent=2)
    f.write("\n")
sys.exit(2 if unparseable else 0)
PYMERGE
    if [[ $MERGE_RC -eq 0 && -f "$SETTINGS_FILE.vhir-new" ]]; then
        replace_file "$SETTINGS_FILE.vhir-new" "$SETTINGS_FILE"
        ok "settings.json (merged)"
    elif [[ $MERGE_RC -eq 2 && -f "$SETTINGS_FILE.vhir-new" ]]; then
        replace_file "$SETTINGS_FILE.vhir-new" "$SETTINGS_FILE"
        warn "settings.json wasn't valid JSON: replaced (backed up above)."
    else
        rm -f "$SETTINGS_FILE.vhir-new"
        warn "settings.json merge failed (exit $MERGE_RC): NOT changed."
    fi
elif [[ -f "$SETTINGS_FILE" ]]; then
    warn "python3 not found. Replacing the existing settings.json."
    echo "$SETTINGS_CONTENT" > "$SETTINGS_FILE.vhir-new"
    replace_file "$SETTINGS_FILE.vhir-new" "$SETTINGS_FILE"
    ok "settings.json (replaced)"
else
    echo "$SETTINGS_CONTENT" > "$SETTINGS_FILE"
    ok "settings.json (hooks + permissions + sandbox)"
fi

# ---- Fetch assets from GitHub ----

GITHUB_RAW="https://raw.githubusercontent.com/AppliedIR"
ERRORS=0

info "Fetching CLAUDE.md..."
if curl -fsSL "$GITHUB_RAW/sift-mcp/main/claude-code/full/CLAUDE.md" -o "$DEPLOY_DIR/CLAUDE.md" 2>/dev/null; then
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
if curl -fsSL "$GITHUB_RAW/sift-mcp/main/claude-code/full/FORENSIC_DISCIPLINE.md" -o "$DEPLOY_DIR/FORENSIC_DISCIPLINE.md" 2>/dev/null; then
    ok "FORENSIC_DISCIPLINE.md"
else
    warn "Could not fetch FORENSIC_DISCIPLINE.md"
    ERRORS=$((ERRORS + 1))
fi

# Skills and the finding skeptic's agent
fetch_skills "$DEPLOY_DIR/.claude/skills"
mkdir -p "$DEPLOY_DIR/.claude/agents"
if curl -fsSL "$GITHUB_RAW/sift-mcp/main/agents/finding-skeptic/claude.md" -o "$DEPLOY_DIR/.claude/agents/finding-skeptic.md" 2>/dev/null; then
    ok "finding-skeptic agent"
else
    warn "Could not fetch the finding-skeptic agent"
    ERRORS=$((ERRORS + 1))
fi

info "Fetching forensic-audit.sh..."
if curl -fsSL "$GITHUB_RAW/sift-mcp/main/claude-code/shared/hooks/forensic-audit.sh" -o "$DEPLOY_DIR/.claude/hooks/forensic-audit.sh" 2>/dev/null; then
    chmod 755 "$DEPLOY_DIR/.claude/hooks/forensic-audit.sh"
    ok "forensic-audit.sh"
else
    warn "Could not fetch forensic-audit.sh"
    ERRORS=$((ERRORS + 1))
fi


if (( ERRORS > 0 )); then
    warn "$ERRORS asset(s) could not be fetched. Re-run or download manually."
fi

fi  # end CLIENT == claude-code

# =============================================================================
# Summary
# =============================================================================

header "Setup Complete"

echo "Gateway:     $GATEWAY_URL"
echo "Workspace:   $DEPLOY_DIR"

echo ""
echo -e "${BOLD}SSH Access${NC}"
echo "  Approvals and rejections are signed in the Examiner Portal, or at the"
echo "  SIFT terminal over SSH (vhir approve, vhir reject). Evidence unlocking"
echo "  (vhir evidence unlock) and command execution (vhir execute) need SSH."
echo "  These operations need the examiner's passphrase or terminal confirmation"
echo "  and are not available through MCP. All other operations are available"
echo "  through MCP tools."

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
    echo "  Alternatively, use an MCP-only client (LibreChat,"
    echo "  or any client without terminal access) which can only interact"
    echo "  with SIFT through audited MCP tools."

    echo ""
    echo -e "${BOLD}Valhuntir workspace created at ~/vhir/${NC}"
    echo ""
    echo -e "${YELLOW}${BOLD}IMPORTANT:${NC} Always launch Claude Code from ~/vhir/ or a subdirectory."
    echo "Valhuntir's settings (guardrails, MCP tools) only apply when Claude Code"
    echo "is started from within this directory. Shell commands on this machine"
    echo "aren't in the case audit, and these settings are user-switchable."
    echo ""
    echo "  cd ~/vhir && claude"
    echo ""
    echo "To organize case work while maintaining controls:"
    echo ""
    echo "  mkdir ~/vhir/cases/INC-2026-001"
    echo "  cd ~/vhir/cases/INC-2026-001 && claude"
fi

echo ""
if [[ "$CLIENT" == "codex" ]]; then
    echo ""
    echo "Start Codex from ~/vhir with Valhuntir's profile:"
    echo ""
    echo "  cd ~/vhir && codex -p valhuntir"
    echo ""
    echo "Not from your home folder: from there its shell could change ~/.vhir."
    echo "Limits on this machine: Codex's shell commands here aren't in the case"
    echo "audit (only the MCP tool calls, run on the SIFT box, are), and these"
    echo "settings are user-switchable: there are no managed Codex settings here."
fi

echo -e "${BOLD}Documentation:${NC} https://appliedir.github.io/Valhuntir/"
echo ""
