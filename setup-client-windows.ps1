#Requires -Version 5.1
<#
.SYNOPSIS
    ValiHuntIR LLM Client Setup for Windows

.DESCRIPTION
    Joins the SIFT gateway and creates a functional $HOME\vhir\ workspace
    with MCP config, forensic controls, and discipline docs.

.PARAMETER Sift
    Gateway URL (required). Example: https://192.168.1.100:4508

.PARAMETER Code
    Join code (required). Generated on SIFT with: vhir setup join-code

.PARAMETER Uninstall
    Remove ValiHuntIR workspace and forensic controls.

.PARAMETER Help
    Show help and exit.

.EXAMPLE
    .\setup-client-windows.ps1 -Sift https://192.168.1.100:4508 -Code XXXX-XXXX
.EXAMPLE
    .\setup-client-windows.ps1 -Uninstall
#>
param(
    [string]$Sift,
    [string]$Code,
    [switch]$Uninstall,
    [switch]$Help
)

# =============================================================================
# Helpers
# =============================================================================

function Write-Info  { param([string]$Msg) Write-Host "[INFO] $Msg" -ForegroundColor Blue }
function Write-Ok    { param([string]$Msg) Write-Host "[OK] $Msg" -ForegroundColor Green }
function Write-Warn  { param([string]$Msg) Write-Host "[WARN] $Msg" -ForegroundColor Yellow }
function Write-Err   { param([string]$Msg) Write-Host "[ERROR] $Msg" -ForegroundColor Red }

function Prompt-YN {
    param([string]$Msg, [bool]$Default = $true)
    if ($Default) { $suffix = "[Y/n]" } else { $suffix = "[y/N]" }
    $answer = Read-Host "$Msg $suffix"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
    return ($answer.Trim().ToLower() -eq "y")
}

function Prompt-YN-Strict {
    param([string]$Msg)
    while ($true) {
        $answer = Read-Host "$Msg [y/n]"
        if ($answer.Trim().ToLower() -eq "y") { return $true }
        if ($answer.Trim().ToLower() -eq "n") { return $false }
        Write-Host "    Please enter y or n."
    }
}

# =============================================================================
# Banner + Help
# =============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  ValiHuntIR - LLM Client Setup (Windows)" -ForegroundColor White
Write-Host "  Artificial Intelligence Incident Response" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

if ($Help) {
    Write-Host "Usage: .\setup-client-windows.ps1 -Sift URL -Code CODE"
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -Sift URL     Gateway URL (required)"
    Write-Host "  -Code CODE    Join code (required)"
    Write-Host "  -Uninstall    Remove ValiHuntIR workspace"
    Write-Host "  -Help         Show this help"
    exit 0
}

# =============================================================================
# Uninstall
# =============================================================================

if ($Uninstall) {
    $deployDir = Join-Path $HOME "vhir"
    Write-Host ""
    Write-Host "ValiHuntIR Forensic Controls - Uninstall" -ForegroundColor White
    Write-Host ""

    if (-not (Test-Path $deployDir)) {
        Write-Info "No ValiHuntIR workspace found at $deployDir."
        exit 0
    }

    Write-Host "  ValiHuntIR workspace: $deployDir"
    $casesDir = Join-Path $deployDir "cases"
    if (Test-Path $casesDir) {
        Write-Host ""
        Write-Host "  WARNING: $casesDir contains case data." -ForegroundColor Yellow
        Write-Host "  Back up case data before removing the workspace."
    }
    Write-Host ""

    if (Prompt-YN-Strict "  Remove entire ValiHuntIR workspace ($deployDir)?") {
        Remove-Item -Path $deployDir -Recurse -Force
        $configYaml = Join-Path $HOME ".vhir" "config.yaml"
        if (Test-Path $configYaml) { Remove-Item -Path $configYaml -Force }
        Write-Ok "Removed $deployDir"
    } else {
        Write-Host ""
        Write-Host "  Removing config files only (preserving cases/)..."
        $claudeDir = Join-Path $deployDir ".claude"
        $mcpJson = Join-Path $deployDir ".mcp.json"
        if (Test-Path $claudeDir) { Remove-Item -Path $claudeDir -Recurse -Force }
        if (Test-Path $mcpJson) { Remove-Item -Path $mcpJson -Force }
        foreach ($f in @("CLAUDE.md", "AGENTS.md", "FORENSIC_DISCIPLINE.md", "TOOL_REFERENCE.md")) {
            $fp = Join-Path $deployDir $f
            if (Test-Path $fp) { Remove-Item -Path $fp -Force }
        }
        $configYaml = Join-Path $HOME ".vhir" "config.yaml"
        if (Test-Path $configYaml) { Remove-Item -Path $configYaml -Force }
        Write-Ok "Config files removed. $casesDir preserved."
    }

    Write-Host ""
    Write-Host "Uninstall complete."
    exit 0
}

# =============================================================================
# Validate
# =============================================================================

if (-not $Sift) {
    Write-Err "Gateway URL is required: -Sift https://IP:4508"
    exit 1
}
if (-not $Code) {
    Write-Err "Join code is required: -Code XXXX-XXXX"
    exit 1
}

$Sift = $Sift.TrimEnd('/')

# =============================================================================
# Join Gateway
# =============================================================================

# Validate join code format
if ($Code -notmatch '^[A-Za-z0-9_-]+$') {
    Write-Err "Invalid join code format (alphanumeric, dash, underscore only)"
    exit 1
}

Write-Info "Joining gateway at $Sift..."

$hostname = [System.Net.Dns]::GetHostName()
$body = @{
    code = $Code
    machine_type = "examiner"
    hostname = $hostname
} | ConvertTo-Json

try {
    # Allow self-signed certs
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $response = Invoke-WebRequest -Uri "$Sift/api/v1/setup/join" `
            -Method Post -ContentType "application/json" -Body $body `
            -SkipCertificateCheck -UseBasicParsing
    } else {
        # PowerShell 5.1 — bypass cert validation
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        $response = Invoke-WebRequest -Uri "$Sift/api/v1/setup/join" `
            -Method Post -ContentType "application/json" -Body $body `
            -UseBasicParsing
    }
} catch {
    Write-Err "Failed to connect to gateway at $Sift"
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
}

$json = $response.Content | ConvertFrom-Json

if ($json.error) {
    Write-Err "Join failed: $($json.error)"
    exit 1
}

if (-not $json.gateway_token) {
    Write-Err "Unexpected response from gateway"
    exit 1
}

$gatewayToken = $json.gateway_token
$gatewayUrl = if ($json.gateway_url) { $json.gateway_url } else { $Sift }
$backends = $json.backends

Write-Ok "Joined gateway"

# Store token
$vhirDir = Join-Path $HOME ".vhir"
if (-not (Test-Path $vhirDir)) {
    New-Item -ItemType Directory -Path $vhirDir -Force | Out-Null
}

$configFile = Join-Path $vhirDir "config.yaml"
@"
gateway_url: "$gatewayUrl"
gateway_token: "$gatewayToken"
"@ | Set-Content -Path $configFile -Encoding UTF8

# Restrict config.yaml to current user only
try {
    $acl = Get-Acl $configFile
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
        "FullControl", "Allow")
    $acl.AddAccessRule($rule)
    Set-Acl -Path $configFile -AclObject $acl
} catch {
    Write-Warn "Could not restrict permissions on $configFile`: $($_.Exception.Message)"
}

Write-Ok "Credentials saved to $configFile"

# =============================================================================
# Workspace Setup
# =============================================================================

Write-Host ""
Write-Host "=== ValiHuntIR Workspace ===" -ForegroundColor White
Write-Host ""

$deployDir = Join-Path $HOME "vhir"
$casesDir = Join-Path $deployDir "cases"
$claudeDir = Join-Path $deployDir ".claude"
$hooksDir = Join-Path $claudeDir "hooks"

New-Item -ItemType Directory -Path $casesDir -Force | Out-Null

# ---- MCP Config ----

$mcpServers = @{}

foreach ($backend in $backends) {
    $mcpServers[$backend] = @{
        type = "streamable-http"
        url = "$gatewayUrl/mcp/$backend"
        headers = @{
            Authorization = "Bearer $gatewayToken"
        }
    }
}

# External MCPs
$mcpServers["zeltser-ir-writing"] = @{
    type = "streamable-http"
    url = "https://website-mcp.zeltser.com/mcp"
}

$mcpServers["microsoft-learn"] = @{
    type = "streamable-http"
    url = "https://learn.microsoft.com/api/mcp"
}

$mcpConfig = @{ mcpServers = $mcpServers }

# Build stdio-format config for Claude Desktop (mcp-remote bridge)
$mcpServersStdio = @{}
foreach ($backend in $backends) {
    $mcpServersStdio[$backend] = @{
        command = "npx"
        args = @("-y", "mcp-remote", "$gatewayUrl/mcp/$backend",
                 "--header", "Authorization:`${AUTH_HEADER}")
        env = @{ AUTH_HEADER = "Bearer $gatewayToken" }
    }
}
$mcpServersStdio["zeltser-ir-writing"] = @{
    command = "npx"
    args = @("-y", "mcp-remote", "https://website-mcp.zeltser.com/mcp")
}
$mcpServersStdio["microsoft-learn"] = @{
    command = "npx"
    args = @("-y", "mcp-remote", "https://learn.microsoft.com/api/mcp")
}
$mcpConfigStdio = @{ mcpServers = $mcpServersStdio }

# ---- Client Choice ----

Write-Host ""
Write-Host "  Which LLM client?"
Write-Host "  1. Claude Code"
Write-Host "  2. Claude Desktop"
Write-Host "  3. LibreChat"
Write-Host "  4. Other"
Write-Host ""
$clientChoice = Read-Host "  Choose [1]"
if (-not $clientChoice) { $clientChoice = "1" }
$clientType = switch ($clientChoice) {
    "1" { "claude-code" }
    "2" { "claude-desktop" }
    "3" { "librechat" }
    default { "other" }
}

# ---- Write client-specific config ----

switch ($clientType) {
    "claude-code" {
        $mcpJsonPath = Join-Path $deployDir ".mcp.json"
        $mcpConfig | ConvertTo-Json -Depth 5 | Set-Content -Path $mcpJsonPath -Encoding UTF8
        $acl = Get-Acl $mcpJsonPath
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            "FullControl", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl -Path $mcpJsonPath -AclObject $acl
        Write-Ok "Written: $mcpJsonPath"
    }
    "claude-desktop" {
        if (-not (Get-Command npx -ErrorAction SilentlyContinue)) {
            Write-Warn "Claude Desktop requires npx (Node.js) for mcp-remote bridge."
            Write-Warn "Install Node.js: https://nodejs.org/"
            Write-Warn "Skipping Claude Desktop config generation."
        } else {
            $claudeDir2 = Join-Path $env:APPDATA "Claude"
            if (-not (Test-Path $claudeDir2)) {
                New-Item -ItemType Directory -Path $claudeDir2 -Force | Out-Null
            }
            $configPath = Join-Path $claudeDir2 "claude_desktop_config.json"
            $mcpConfigStdio | ConvertTo-Json -Depth 5 | Set-Content -Path $configPath -Encoding UTF8
            Write-Ok "Written: $configPath (stdio via mcp-remote)"
        }
    }
    "librechat" {
        $configPath = Join-Path $deployDir "librechat_mcp.yaml"
        $mcpConfig | ConvertTo-Json -Depth 5 | Set-Content -Path $configPath -Encoding UTF8
        Write-Ok "Written: $configPath (merge into librechat.yaml)"
    }
    default {
        $configPath = Join-Path $deployDir "vhir-mcp-config.json"
        $mcpConfig | ConvertTo-Json -Depth 5 | Set-Content -Path $configPath -Encoding UTF8
        Write-Ok "Written: $configPath (reference config)"
        Write-Info "Configure your LLM client using the entries in this file."
    }
}

# ---- Claude Code assets (skip for other clients) ----

if ($clientType -eq "claude-code") {

New-Item -ItemType Directory -Path $hooksDir -Force | Out-Null

# ---- Settings.json ----

$settingsPath = Join-Path $claudeDir "settings.json"
$hookPath = Join-Path $hooksDir "forensic-audit.sh"

$settingsObj = @{
    hooks = @{
        UserPromptSubmit = @(
            @{
                matcher = ""
                hooks = @(
                    @{
                        type = "command"
                        command = "cat << 'EOF'`n<forensic-rules>`nPLAN before 3+ steps | EVIDENCE for claims | APPROVAL before conclusions`nRECORD actions via forensic-mcp | NO DELETE without approval`n</forensic-rules>`nEOF"
                    }
                )
            }
        )
        PostToolUse = @(
            @{
                matcher = "Bash"
                hooks = @(
                    @{
                        type = "command"
                        command = $hookPath.Replace('\', '/')
                    }
                )
            }
        )
    }
    permissions = @{
        allow = @(
            "mcp__forensic-mcp__*",
            "mcp__case-mcp__*",
            "mcp__sift-mcp__*",
            "mcp__report-mcp__*",
            "mcp__forensic-rag-mcp__*",
            "mcp__windows-triage-mcp__*",
            "mcp__opencti-mcp__*",
            "mcp__wintools-mcp__*",
            "mcp__remnux-mcp__*",
            "mcp__vhir__*",
            "mcp__zeltser-ir-writing__*",
            "mcp__microsoft-learn__*"
        )
        deny = @(
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
            "Read(/var/lib/vhir/**)",
            "Edit(/var/lib/vhir/**)",
            "Write(/var/lib/vhir/**)",
            "Bash(vhir approve*)",
            "Bash(*vhir approve*)",
            "Bash(vhir reject*)",
            "Bash(*vhir reject*)",
            "Edit(**/.claude/settings.json)",
            "Write(**/.claude/settings.json)",
            "Edit(**/.claude/CLAUDE.md)",
            "Write(**/.claude/CLAUDE.md)",
            "Edit(**/.claude/rules/**)",
            "Write(**/.claude/rules/**)",
            "Edit(**/.vhir/hooks/**)",
            "Write(**/.vhir/hooks/**)",
            "Edit(**/.vhir/active_case)",
            "Write(**/.vhir/active_case)",
            "Edit(**/.vhir/gateway.yaml)",
            "Write(**/.vhir/gateway.yaml)",
            "Edit(**/.vhir/config.yaml)",
            "Write(**/.vhir/config.yaml)",
            "Edit(**/.vhir/.password_lockout)",
            "Write(**/.vhir/.password_lockout)",
            "Edit(**/pending-reviews.json)",
            "Write(**/pending-reviews.json)"
        )
    }
    sandbox = @{
        enabled = $true
        allowUnsandboxedCommands = $false
        filesystem = @{
            denyWrite = @(
                "~/.vhir/gateway.yaml",
                "~/.vhir/config.yaml",
                "~/.vhir/active_case",
                "~/.vhir/hooks",
                "~/.vhir/.password_lockout",
                "~/.vhir/.pin_lockout",
                "~/.claude/settings.json",
                "~/.claude/CLAUDE.md",
                "~/.claude/rules"
            )
        }
    }
}

if (Test-Path $settingsPath) {
    Write-Info "Existing settings.json found. Merging..."
    try {
        $existing = Get-Content -Path $settingsPath -Raw | ConvertFrom-Json

        # Merge hooks
        if (-not $existing.hooks) {
            $existing | Add-Member -NotePropertyName hooks -NotePropertyValue $settingsObj.hooks
        } else {
            foreach ($hookType in @("UserPromptSubmit", "PreToolUse", "PostToolUse")) {
                if (-not $existing.hooks.$hookType) {
                    $existing.hooks | Add-Member -NotePropertyName $hookType -NotePropertyValue $settingsObj.hooks.$hookType
                }
            }
        }

        # Merge permissions
        if (-not $existing.permissions) {
            $existing | Add-Member -NotePropertyName permissions -NotePropertyValue $settingsObj.permissions
        } else {
            # Merge allow
            if (-not $existing.permissions.allow) {
                $existing.permissions | Add-Member -NotePropertyName allow -NotePropertyValue $settingsObj.permissions.allow
            } else {
                $existingAllow = [System.Collections.Generic.HashSet[string]]::new([string[]]$existing.permissions.allow)
                foreach ($rule in $settingsObj.permissions.allow) {
                    [void]$existingAllow.Add($rule)
                }
                $existing.permissions.allow = ($existingAllow | Sort-Object)
            }
            # Merge deny
            if (-not $existing.permissions.deny) {
                $existing.permissions | Add-Member -NotePropertyName deny -NotePropertyValue $settingsObj.permissions.deny
            } else {
                $existingDeny = [System.Collections.Generic.HashSet[string]]::new([string[]]$existing.permissions.deny)
                # Remove old forensic rules on re-deploy
                foreach ($old in @("Bash(rm -rf *)", "Bash(mkfs*)", "Bash(dd *)")) {
                    [void]$existingDeny.Remove($old)
                }
                foreach ($rule in $settingsObj.permissions.deny) {
                    [void]$existingDeny.Add($rule)
                }
                $existing.permissions.deny = ($existingDeny | Sort-Object)
            }
        }

        # Merge sandbox
        if (-not $existing.sandbox) {
            $existing | Add-Member -NotePropertyName sandbox -NotePropertyValue $settingsObj.sandbox
        }

        $existing | ConvertTo-Json -Depth 10 | Set-Content -Path $settingsPath -Encoding UTF8
        Write-Ok "settings.json (merged)"
    } catch {
        Write-Warn "Could not merge existing settings. Overwriting."
        $settingsObj | ConvertTo-Json -Depth 10 | Set-Content -Path $settingsPath -Encoding UTF8
        Write-Ok "settings.json (overwritten)"
    }
} else {
    $settingsObj | ConvertTo-Json -Depth 10 | Set-Content -Path $settingsPath -Encoding UTF8
    Write-Ok "settings.json (hooks + permissions + sandbox)"
}

# ---- Fetch assets from GitHub ----

$githubRaw = "https://raw.githubusercontent.com/AppliedIR"
$errors = 0

$assets = @(
    @{ Name = "CLAUDE.md"; Url = "$githubRaw/sift-mcp/main/claude-code/CLAUDE.md"; Dest = (Join-Path $deployDir "CLAUDE.md") },
    @{ Name = "AGENTS.md"; Url = "$githubRaw/sift-mcp/main/AGENTS.md"; Dest = (Join-Path $deployDir "AGENTS.md") },
    @{ Name = "FORENSIC_DISCIPLINE.md"; Url = "$githubRaw/sift-mcp/main/claude-code/FORENSIC_DISCIPLINE.md"; Dest = (Join-Path $deployDir "FORENSIC_DISCIPLINE.md") },
    @{ Name = "TOOL_REFERENCE.md"; Url = "$githubRaw/sift-mcp/main/claude-code/TOOL_REFERENCE.md"; Dest = (Join-Path $deployDir "TOOL_REFERENCE.md") },
    @{ Name = "forensic-audit.sh"; Url = "$githubRaw/sift-mcp/main/claude-code/hooks/forensic-audit.sh"; Dest = $hookPath }
)

foreach ($asset in $assets) {
    Write-Info "Fetching $($asset.Name)..."
    try {
        Invoke-WebRequest -Uri $asset.Url -OutFile $asset.Dest -UseBasicParsing
        Write-Ok $asset.Name
    } catch {
        Write-Warn "Could not fetch $($asset.Name)"
        $errors++
    }
}

# Note: forensic-audit.sh is a POSIX shell script. Claude Code hooks on Windows
# run via the shell. This script may require WSL or Git Bash to execute.

if ($errors -gt 0) {
    Write-Warn "$errors asset(s) could not be fetched. Re-run or download manually."
}

}  # end clientType -eq "claude-code"

# =============================================================================
# Summary
# =============================================================================

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor White
Write-Host ""

Write-Host "Gateway:     $gatewayUrl"
Write-Host "Workspace:   $deployDir"

Write-Host ""
Write-Host "SSH Access" -ForegroundColor White
Write-Host "  SSH access to SIFT is required for finding approval and rejection"
Write-Host "  (vhir approve, vhir reject), evidence unlocking (vhir evidence"
Write-Host "  unlock), and command execution (vhir execute). These operations"
Write-Host "  require password or terminal confirmation and are not available through"
Write-Host "  MCP. All other operations are available through MCP tools."
Write-Host ""
Write-Host "  Windows SSH clients: OpenSSH (built-in), PuTTY, or Windows Terminal."
Write-Host "  If using ssh-agent or pageant, configure per-use confirmation to"
Write-Host "  prevent automated key access."

if ($clientType -eq "claude-code") {
    Write-Host ""
    Write-Host "SSH Security Advisory" -ForegroundColor Yellow
    Write-Host "  Claude Code has terminal access and can use your SSH credentials"
    Write-Host "  to run commands directly on SIFT, bypassing MCP audit controls."
    Write-Host "  To mitigate this, ensure your SSH authentication to SIFT requires"
    Write-Host "  human interaction per use:"
    Write-Host "    - Password-only auth (no agent-forwarded keys)"
    Write-Host "    - ssh-agent confirmation per use"
    Write-Host "    - Hardware security keys (FIDO2/U2F)"
    Write-Host ""
    Write-Host "  Alternatively, use an MCP-only client (Claude Desktop, LibreChat,"
    Write-Host "  or any client without terminal access) which can only interact"
    Write-Host "  with SIFT through audited MCP tools."

    Write-Host ""
    Write-Host "ValiHuntIR workspace created at $deployDir\" -ForegroundColor White
    Write-Host ""
    Write-Host "IMPORTANT: Always launch Claude Code from $deployDir\ or a subdirectory." -ForegroundColor Yellow
    Write-Host "Forensic controls (audit logging, guardrails, MCP tools) only apply"
    Write-Host "when Claude Code is started from within this directory."
    Write-Host ""
    Write-Host "  cd $deployDir; claude"
    Write-Host ""
    Write-Host "To organize case work while maintaining controls:"
    Write-Host ""
    Write-Host "  mkdir $deployDir\cases\INC-2026-001"
    Write-Host "  cd $deployDir\cases\INC-2026-001; claude"
}

Write-Host ""
Write-Host "Documentation: https://appliedir.github.io/vhir/" -ForegroundColor White
Write-Host ""
