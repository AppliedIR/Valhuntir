# Deployment Guide

## Installation Tiers

The `setup-sift.sh` installer offers three tiers:

| Tier | Packages | Use Case |
|------|----------|----------|
| **Quick** | forensic-mcp, case-mcp, report-mcp, sift-mcp, sift-gateway, sift-common, forensic-knowledge | Core investigation. Minimal install. |
| **Recommended** | Quick + forensic-rag, windows-triage | Adds RAG search and baseline validation. |
| **Custom** | Select individual packages | Fine-grained control. |

OpenCTI-mcp is always optional (requires an OpenCTI instance).

## SIFT Workstation Setup

### Prerequisites

- Ubuntu 22.04+ (SIFT Workstation recommended)
- Python 3.10+
- Git
- sudo access (required — creates the HMAC verification ledger at `/var/lib/vhir/verification/`)

### Install

```bash
git clone https://github.com/AppliedIR/sift-mcp.git && cd sift-mcp
./setup-sift.sh
```

The installer:
1. Creates a Python virtual environment
2. Installs MCP servers, gateway, and vhir CLI via pip
3. Creates the HMAC verification ledger directory at `/var/lib/vhir/verification/` (requires sudo)
4. Sets examiner identity
5. Generates `gateway.yaml` configuration
6. Creates a systemd service for the gateway (optional)
7. Starts the gateway
8. Runs `vhir setup client` to configure your LLM client

## Windows Workstation Setup

### Prerequisites

- Windows 10/11 or Windows Server 2019+
- Python 3.10+
- Forensic tools (Zimmerman suite, Hayabusa) installed

### Install

```powershell
git clone https://github.com/AppliedIR/wintools-mcp.git
cd wintools-mcp
.\scripts\setup-windows.ps1
```

The installer:
1. Requires typing `security_hole` to acknowledge the security implications
2. Creates a Python virtual environment
3. Installs the wintools-mcp package
4. Generates a bearer token (`vhir_wt_` prefix)
5. Creates `config.yaml` with the token
6. Optionally creates a Windows service

### Connecting to SIFT

Copy the bearer token from the installer output. On the SIFT workstation, add a wintools backend to `gateway.yaml`:

```yaml
backends:
  wintools-mcp:
    type: http
    url: "http://WIN_IP:4624/mcp"
    bearer_token: "vhir_wt_..."
```

Or use `vhir setup client` with the `--windows` flag:

```bash
vhir setup client --sift=http://127.0.0.1:4508 --windows=WIN_IP:4624
```

### SMB Configuration

wintools-mcp accesses the case directory on SIFT via SMB for audit trail writes. Set `VHIR_SHARE_ROOT` to the SMB mount point:

```powershell
$env:VHIR_SHARE_ROOT = "E:\cases\SRL2\"
```

## Remote Access (TLS + Auth)

For deployments where the LLM client runs on a different machine:

### Enable Remote Access

```bash
./setup-sift.sh --remote
```

This generates:
- Local CA certificate and gateway TLS certificate at `~/.vhir/tls/`
- Bearer token (`vhir_gw_` prefix) in `gateway.yaml`
- Gateway binds to `0.0.0.0:4508` with TLS

The installer prints per-OS remote client setup commands with a join code.

### Remote Client Setup

Run the appropriate setup script on the machine where your LLM client runs. Each script joins the gateway and creates a `~/vhir/` workspace with MCP config, forensic controls, and discipline docs.

**Linux:**
```bash
curl -sSL https://raw.githubusercontent.com/AppliedIR/valihuntir/main/setup-client-linux.sh \
  | bash -s -- --sift=https://SIFT_IP:4508 --code=XXXX-XXXX
```

**macOS:**
```bash
curl -sSL https://raw.githubusercontent.com/AppliedIR/valihuntir/main/setup-client-macos.sh \
  | bash -s -- --sift=https://SIFT_IP:4508 --code=XXXX-XXXX
```

**Windows:**
```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/AppliedIR/valihuntir/main/setup-client-windows.ps1 -OutFile setup-client-windows.ps1
.\setup-client-windows.ps1 -Sift https://SIFT_IP:4508 -Code XXXX-XXXX
```

Always launch your LLM client from `~/vhir/` or a subdirectory. Forensic controls only apply when started from within the workspace.

```bash
cd ~/vhir && claude                          # start from workspace root
mkdir ~/vhir/cases/INC-2026-001              # organize by case
cd ~/vhir/cases/INC-2026-001 && claude       # case-specific session
```

To uninstall, re-run the setup script with `--uninstall` (Linux/macOS) or `-Uninstall` (Windows). On SIFT, use `vhir setup client --uninstall`.

Your LLM client must run locally on your machine to reach the SIFT gateway. Cloud-hosted LLM services cannot connect to internal network addresses.

### Join Codes

Generate a join code on the SIFT workstation:

```bash
vhir setup join-code --expires 2    # 2-hour expiry
```

## Multi-Examiner Deployment

Each examiner runs their own full stack on their own SIFT workstation with a local case directory.

### Setup

Each examiner installs independently:

```bash
git clone https://github.com/AppliedIR/sift-mcp.git && cd sift-mcp
./setup-sift.sh
```

### Collaboration

Examiners share findings via JSON export/import:

```bash
# Alice exports her findings
vhir export --file findings-alice.json

# Bob imports Alice's findings
vhir merge --file findings-alice.json
```

IDs include the examiner name (`F-alice-001`, `F-bob-003`) so they never collide. Merge uses last-write-wins by `modified_at` timestamp. APPROVED findings are protected from overwrite.

## Gateway Configuration

The gateway is configured via `gateway.yaml` (typically at `~/.vhir/gateway.yaml`).

### Backend Configuration

```yaml
backends:
  forensic-mcp:
    type: stdio
    command: ["python", "-m", "forensic_mcp"]
  case-mcp:
    type: stdio
    command: ["python", "-m", "case_mcp"]
  report-mcp:
    type: stdio
    command: ["python", "-m", "report_mcp"]
  sift-mcp:
    type: stdio
    command: ["python", "-m", "sift_mcp"]
  forensic-rag-mcp:
    type: stdio
    command: ["python", "-m", "rag_mcp"]
  windows-triage-mcp:
    type: stdio
    command: ["python", "-m", "windows_triage"]
  opencti-mcp:
    type: stdio
    command: ["python", "-m", "opencti_mcp"]
  wintools-mcp:
    type: http
    url: "http://WIN_IP:4624/mcp"
    bearer_token: "vhir_wt_..."
```

### Authentication

```yaml
api_keys:
  vhir_gw_a1b2c3d4e5f6a1b2c3d4e5f6:
    examiner: "alice"
    role: "examiner"
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SIFT_TIMEOUT` | `600` | Default command timeout (seconds) |
| `SIFT_TOOL_PATHS` | (none) | Extra binary search paths (colon-separated) |
| `SIFT_HAYABUSA_DIR` | `/opt/hayabusa` | Hayabusa install location |
| `VHIR_CASE_DIR` | (none) | Active case directory (falls back to `~/.vhir/active_case`) |
| `VHIR_CASES_DIR` | (none) | Root directory containing all cases |
| `VHIR_EXAMINER` | (none) | Examiner identity |

### wintools-mcp Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WINTOOLS_TIMEOUT` | `600` | Default command timeout (seconds) |
| `WINTOOLS_HOST` | `127.0.0.1` | HTTP bind address |
| `WINTOOLS_PORT` | `4624` | HTTP port |
| `WINTOOLS_TOOL_PATHS` | (none) | Additional binary search directories |
| `VHIR_SHARE_ROOT` | (none) | SMB mount root for evidence and extractions |
| `VHIR_EXAMINER` | OS user | Examiner identity |

## Client Configuration

### Claude Code

`vhir setup client --client=claude-code` deploys:

- `.mcp.json` with Streamable HTTP endpoint
- `.claude/settings.json` with kernel-level sandbox, case data deny rules, PreToolUse guard hook, and PostToolUse audit hook
- `FORENSIC_DISCIPLINE.md` and `TOOL_REFERENCE.md` for LLM context
- `CLAUDE.md` referencing AGENTS.md

### Claude Desktop

`vhir setup client --client=claude-desktop` generates `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vhir": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://127.0.0.1:4508/mcp",
               "--header", "Authorization:${AUTH_HEADER}"],
      "env": { "AUTH_HEADER": "Bearer <your-token>" }
    }
  }
}
```

### External MCPs

Two external MCPs are configured during client setup:

- **Zeltser IR Writing MCP** (`https://website-mcp.zeltser.com/mcp`) — Required for report generation
- **MS Learn MCP** (`https://learn.microsoft.com/api/mcp`) — Optional, Microsoft documentation search

## Systemd Service

The installer can create a systemd service for the gateway:

```bash
sudo systemctl enable vhir-gateway
sudo systemctl start vhir-gateway
sudo systemctl status vhir-gateway
```

Logs:
```bash
journalctl -u vhir-gateway -f
```

## Testing Connectivity

```bash
vhir setup test    # Test all configured MCP endpoints
```

This verifies connectivity to the gateway and all backend MCPs.
