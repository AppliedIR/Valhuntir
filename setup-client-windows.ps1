#Requires -Version 5.1
<#
.SYNOPSIS
    Valhuntir LLM Client Setup for Windows

.DESCRIPTION
    Joins the SIFT gateway and creates a functional $HOME\vhir\ workspace
    with MCP config, forensic controls, and discipline docs.

.PARAMETER Sift
    Gateway URL (required). Example: https://192.168.1.100:4508

.PARAMETER Code
    Join code (required). Generated on SIFT with: vhir setup join-code

.PARAMETER Uninstall
    Remove Valhuntir workspace and forensic controls.

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

# A user's file is backed up before it's changed, with the command that puts it back.
function Backup-UserFile {
    param([string]$Path)
    $base = "$Path.vhir-backup-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))"
    $bak = $base; $n = 1
    while (Test-Path -LiteralPath $bak) { $n++; $bak = "$base-$n" }
    Copy-Item -LiteralPath $Path -Destination $bak -ErrorAction Stop
    Write-Warn "Backed up $Path -> $bak"
    $q = { param($s) "'" + ($s -replace "'", "''") + "'" }
    Write-Host "    To undo: Copy-Item -LiteralPath $(& $q $bak) -Destination $(& $q $Path) -Force"
}
# Write new text over a file, backing the file up first if that changes it.
# Returns whether it was written: not when the backup fails.
function Set-UserFile {
    param([string]$Path, [string]$Text)
    $tmp = "$Path.vhir-new"
    Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue  # only this run's text
    try { $Text | Set-Content -LiteralPath $tmp -Encoding UTF8 -ErrorAction Stop } catch {
        Write-Warn "Could not write ${tmp}: $($_.Exception.Message). $Path NOT changed."
        return $false
    }
    $new = [IO.File]::ReadAllBytes($tmp)
    Remove-Item -LiteralPath $tmp
    if ((Test-Path -LiteralPath $Path) -and
        (($new -join ',') -ne ([IO.File]::ReadAllBytes($Path) -join ','))) {
        try { Backup-UserFile $Path } catch {
            Write-Warn "Could not back up ${Path}: $($_.Exception.Message). NOT changed."
            return $false
        }
    }
    [IO.File]::WriteAllBytes($Path, $new)
    return $true
}

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

# Fetch every skill file skills/MANIFEST lists into $Dest. Each file is fetched
# and replaced: an edit to a vhir skill is lost on re-run. Counts failures in
# $script:errors.
function Fetch-Skills {
    param([string]$Dest)
    Write-Info "Fetching skills..."
    try {
        $manifest = (Invoke-WebRequest -Uri "$githubRaw/sift-mcp/main/skills/MANIFEST" -UseBasicParsing).Content
    } catch {
        Write-Warn "Could not fetch the skills list"
        $script:errors++
        return
    }
    if ($manifest -is [byte[]]) { $manifest = [System.Text.Encoding]::UTF8.GetString($manifest) }
    $fetched = 0
    foreach ($rel in ($manifest -split "`r?`n")) {
        if (-not $rel -or $rel.StartsWith("#")) { continue }
        if ($rel -notmatch '^[A-Za-z0-9._/-]+$' -or $rel.Contains("..") -or $rel.StartsWith("/")) {
            Write-Warn "Skipped an unexpected skills path: $rel"
            $script:errors++
            continue
        }
        $target = Join-Path $Dest ($rel -replace '/', '\')
        New-Item -ItemType Directory -Force -Path (Split-Path $target -Parent) | Out-Null
        try {
            Invoke-WebRequest -Uri "$githubRaw/sift-mcp/main/skills/$rel" -OutFile $target -UseBasicParsing
            $fetched++
        } catch {
            Write-Warn "Could not fetch skills/$rel"
            $script:errors++
        }
    }
    Write-Ok "$fetched skill files"
}


# =============================================================================
# Banner + Help
# =============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  Valhuntir - LLM Client Setup (Windows)" -ForegroundColor White
Write-Host "  AI-Assisted Forensic Investigation" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

if ($Help) {
    Write-Host "Usage: .\setup-client-windows.ps1 -Sift URL -Code CODE"
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -Sift URL     Gateway URL (required)"
    Write-Host "  -Code CODE    Join code (required)"
    Write-Host "  -Uninstall    Remove Valhuntir workspace"
    Write-Host "  -Help         Show this help"
    exit 0
}

# =============================================================================
# Uninstall
# =============================================================================

if ($Uninstall) {
    $deployDir = Join-Path $HOME "vhir"
    Write-Host ""
    Write-Host "Valhuntir Forensic Controls - Uninstall" -ForegroundColor White
    Write-Host ""

    # Codex: Valhuntir's profile, skills and agent (never ~/.codex/config.toml)
    $codexFiles = @()
    foreach ($f in @((Join-Path $HOME (Join-Path ".codex" "valhuntir.config.toml")),
                     (Join-Path $HOME (Join-Path ".codex" (Join-Path "agents" "finding-skeptic.toml"))))) {
        if (Test-Path -LiteralPath $f -PathType Leaf) { $codexFiles += $f }
    }
    $agentSkills = Join-Path $HOME (Join-Path ".agents" "skills")
    if (Test-Path -LiteralPath $agentSkills) {
        $codexFiles += Get-ChildItem -LiteralPath $agentSkills -Directory |
            Where-Object { $_.Name -like "vhir-*" -or $_.Name -eq "finding-skeptic" } |
            ForEach-Object { $_.FullName }
    }
    if ($codexFiles.Count -gt 0) {
        Write-Host "  Codex files:"
        $codexFiles | ForEach-Object { Write-Host "    $_" }
        if (Prompt-YN-Strict "  Remove Valhuntir's Codex profile, skills and agent?") {
            $codexFiles | ForEach-Object { Remove-Item -LiteralPath $_ -Recurse -Force }
            Write-Ok "Removed Valhuntir's Codex files"
        }
        Write-Host ""
    }

    if (-not (Test-Path $deployDir)) {
        Write-Info "No Valhuntir workspace found at $deployDir."
        exit 0
    }

    Write-Host "  Valhuntir workspace: $deployDir"
    $casesDir = Join-Path $deployDir "cases"
    if (Test-Path $casesDir) {
        Write-Host ""
        Write-Host "  WARNING: $casesDir contains case data." -ForegroundColor Yellow
        Write-Host "  Back up case data before removing the workspace."
    }
    Write-Host ""

    if (Prompt-YN-Strict "  Remove entire Valhuntir workspace ($deployDir)?") {
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
Write-Host "=== Valhuntir Workspace ===" -ForegroundColor White
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

# ---- Client Choice ----

Write-Host ""
Write-Host "  Which LLM client?"
Write-Host "  1. Claude Code"
Write-Host "  2. Codex"
Write-Host "  3. LibreChat"
Write-Host "  4. Other"
Write-Host ""
Write-Host "  (Claude Desktop isn't offered: its commands aren't audited. Use Claude Code"
Write-Host "  on the SIFT workstation, or Claude Code or Codex here.)"
Write-Host ""
$clientChoice = Read-Host "  Choose [1]"
if (-not $clientChoice) { $clientChoice = "1" }
$clientType = switch ($clientChoice) {
    "1" { "claude-code" }
    "2" { "codex" }
    "3" { "librechat" }
    default { "other" }
}

# ---- Write client-specific config ----

switch ($clientType) {
    "claude-code" {
        $mcpJsonPath = Join-Path $deployDir ".mcp.json"
        if (-not (Set-UserFile $mcpJsonPath ($mcpConfig | ConvertTo-Json -Depth 5))) { break }
        $acl = Get-Acl $mcpJsonPath
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            "FullControl", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl -Path $mcpJsonPath -AclObject $acl
        Write-Ok "Written: $mcpJsonPath"
    }
    "codex" { }  # Valhuntir's Codex profile, below
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

# ---- Codex: Valhuntir's profile, the skills and the skeptic's agent ----
# The profile is ~/.codex/valhuntir.config.toml (codex -p valhuntir); the
# user's ~/.codex/config.toml is never written.

if ($clientType -eq "codex") {
    $githubRaw = "https://raw.githubusercontent.com/AppliedIR"
    $errors = 0
    $codexDir = Join-Path $HOME ".codex"
    $profilePath = Join-Path $codexDir "valhuntir.config.toml"
    New-Item -ItemType Directory -Force -Path (Join-Path $codexDir "agents") | Out-Null
    Fetch-Skills (Join-Path $HOME (Join-Path ".agents" "skills"))
    try {
        Invoke-WebRequest -Uri "$githubRaw/sift-mcp/main/agents/finding-skeptic/codex.toml" -OutFile (Join-Path $codexDir (Join-Path "agents" "finding-skeptic.toml")) -UseBasicParsing
        Write-Ok "finding-skeptic agent"
    } catch {
        Write-Warn "Could not fetch the finding-skeptic agent"
        $errors++
    }
    $parts = @()
    foreach ($part in @("AGENTS.md", "claude-code/full/FORENSIC_DISCIPLINE.md", "codex/OVERLAY.md", "codex/REMOTE.md")) {
        try {
            $c = (Invoke-WebRequest -Uri "$githubRaw/sift-mcp/main/$part" -UseBasicParsing).Content
            if ($c -is [byte[]]) { $c = [System.Text.Encoding]::UTF8.GetString($c) }
            $parts += ($c -replace "`r`n", "`n").Trim()
        } catch {
            Write-Warn "Could not fetch $part"
            $parts = $null
            $errors++
            break
        }
    }
    $quotes = "'" * 3
    $nl = "`n"
    if (-not $parts -or ($parts -join "").Contains($quotes)) {
        Write-Warn "Valhuntir's instructions for Codex couldn't be fetched; $profilePath not written."
    } else {
        $text = "# Valhuntir's Codex profile, for: codex -p valhuntir$nl" +
            "# vhir's client setup writes this file. It holds the$nl" +
            "# gateway token, so only you can read it.$nl" +
            'sandbox_mode = "workspace-write"' + $nl +
            'approval_policy = "on-request"' + $nl +
            "project_doc_max_bytes = 0$nl" +
            "developer_instructions = $quotes$nl" + ($parts -join "$nl$nl") + "$nl$quotes$nl"
        foreach ($b in $backends) {
            if ($b -notmatch '^[A-Za-z0-9_-]+$') { continue }
            $text += "$nl[mcp_servers.$b]$nl" +
                "url = `"$gatewayUrl/mcp/$b`"$nl" +
                "http_headers = { Authorization = `"Bearer $gatewayToken`" }$nl" +
                'default_tools_approval_mode = "approve"' + $nl
        }
        $text += "$nl[mcp_servers.zeltser-ir-writing]$nl" + 'url = "https://website-mcp.zeltser.com/mcp"' + $nl
        $text += "$nl[mcp_servers.microsoft-learn]$nl" + 'url = "https://learn.microsoft.com/api/mcp"' + $nl
        $new = (New-Object System.Text.UTF8Encoding $false).GetBytes($text)  # no BOM
        $write = $true
        if (Test-Path -LiteralPath $profilePath) {
            $old = [IO.File]::ReadAllBytes($profilePath)
            if (($old -join ',') -eq ($new -join ',')) {
                $write = $false
            } else {
                Write-Host "  Changes to ${profilePath}:"
                $before = [IO.File]::ReadAllText($profilePath) -split "`n"
                Compare-Object $before ($text -split "`n") | ForEach-Object {
                    $mark = if ($_.SideIndicator -eq "=>") { "+" } else { "-" }
                    Write-Host ("    " + $mark + ($_.InputObject -replace '(vhir_[a-z]{2}_)[0-9A-Za-z]+', '$1...'))
                }
                try { Backup-UserFile $profilePath } catch {
                    Write-Warn "Could not back up ${profilePath}: $($_.Exception.Message). NOT changed."
                    $write = $false
                }
            }
        }
        if ($write) {
            [IO.File]::WriteAllBytes($profilePath, $new)
            if ($env:OS -eq "Windows_NT") {
                $acl = Get-Acl $profilePath
                $acl.SetAccessRuleProtection($true, $false)
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
                    "FullControl", "Allow")
                $acl.SetAccessRule($rule)
                Set-Acl -Path $profilePath -AclObject $acl
            }
            Write-Ok "Written: $profilePath"
        }
    }
    $codexConfig = Join-Path $codexDir "config.toml"
    if ((Test-Path -LiteralPath $codexConfig) -and
        (Select-String -LiteralPath $codexConfig -Pattern '^\s*sandbox_mode\s*=\s*"danger-full-access"' -Quiet)) {
        Write-Warn "$codexConfig sets sandbox_mode = `"danger-full-access`": that widens Codex's sandbox. vhir doesn't edit that file."
    }
    if ($errors -gt 0) {
        Write-Warn "$errors Codex file(s) could not be fetched. Re-run, or fetch them by hand."
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
            "mcp__threatintel-mcp__*",
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
            "Edit(**/evidence.json)",
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
            "Edit(**/pending-reviews.json)"
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

        if (Set-UserFile $settingsPath ($existing | ConvertTo-Json -Depth 10)) {
            Write-Ok "settings.json (merged)"
        }
    } catch {
        Write-Warn "Could not merge existing settings. Replacing them."
        if (Set-UserFile $settingsPath ($settingsObj | ConvertTo-Json -Depth 10)) {
            Write-Ok "settings.json (replaced)"
        }
    }
} else {
    $settingsObj | ConvertTo-Json -Depth 10 | Set-Content -Path $settingsPath -Encoding UTF8
    Write-Ok "settings.json (hooks + permissions + sandbox)"
}

# ---- Fetch assets from GitHub ----

$githubRaw = "https://raw.githubusercontent.com/AppliedIR"
$errors = 0

$agentsDir = Join-Path $deployDir ".claude\agents"
New-Item -ItemType Directory -Force -Path $agentsDir | Out-Null

$assets = @(
    @{ Name = "CLAUDE.md"; Url = "$githubRaw/sift-mcp/main/claude-code/full/CLAUDE.md"; Dest = (Join-Path $deployDir "CLAUDE.md") },
    @{ Name = "AGENTS.md"; Url = "$githubRaw/sift-mcp/main/AGENTS.md"; Dest = (Join-Path $deployDir "AGENTS.md") },
    @{ Name = "FORENSIC_DISCIPLINE.md"; Url = "$githubRaw/sift-mcp/main/claude-code/full/FORENSIC_DISCIPLINE.md"; Dest = (Join-Path $deployDir "FORENSIC_DISCIPLINE.md") },
    @{ Name = "finding-skeptic.md"; Url = "$githubRaw/sift-mcp/main/agents/finding-skeptic/claude.md"; Dest = (Join-Path $agentsDir "finding-skeptic.md") },
    @{ Name = "forensic-audit.sh"; Url = "$githubRaw/sift-mcp/main/claude-code/shared/hooks/forensic-audit.sh"; Dest = $hookPath }
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

# Skills: every file skills/MANIFEST lists
Fetch-Skills (Join-Path $deployDir ".claude\skills")

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
Write-Host "  Approvals and rejections are signed in the Examiner Portal, or at the"
Write-Host "  SIFT terminal over SSH (vhir approve, vhir reject). Evidence unlocking"
Write-Host "  (vhir evidence unlock) and command execution (vhir execute) need SSH."
Write-Host "  These operations need the examiner's passphrase or terminal confirmation"
Write-Host "  and are not available through MCP. All other operations are available"
Write-Host "  through MCP tools."
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
    Write-Host "  Alternatively, use an MCP-only client (LibreChat,"
    Write-Host "  or any client without terminal access) which can only interact"
    Write-Host "  with SIFT through audited MCP tools."

    Write-Host ""
    Write-Host "Valhuntir workspace created at $deployDir\" -ForegroundColor White
    Write-Host ""
    Write-Host "IMPORTANT: Always launch Claude Code from $deployDir\ or a subdirectory." -ForegroundColor Yellow
    Write-Host "Valhuntir's settings (guardrails, MCP tools) only apply when Claude Code"
    Write-Host "is started from within this directory. Shell commands on this machine"
    Write-Host "aren't in the case audit, and these settings are user-switchable."
    Write-Host ""
    Write-Host "  cd $deployDir; claude"
    Write-Host ""
    Write-Host "To organize case work while maintaining controls:"
    Write-Host ""
    Write-Host "  mkdir $deployDir\cases\INC-2026-001"
    Write-Host "  cd $deployDir\cases\INC-2026-001; claude"
}

Write-Host ""
if ($clientType -eq "codex") {
    Write-Host ""
    Write-Host "Start Codex from ~/vhir with Valhuntir's profile:"
    Write-Host ""
    Write-Host "  cd ~/vhir; codex -p valhuntir"
    Write-Host ""
    Write-Host "Not from your home folder: from there its shell could change ~/.vhir."
    Write-Host "Limits on this machine: Codex's shell commands here aren't in the case"
    Write-Host "audit (only the MCP tool calls, run on the SIFT box, are), and these"
    Write-Host "settings are user-switchable: there are no managed Codex settings here."
    Write-Host ""
}

Write-Host "Documentation: https://appliedir.github.io/Valhuntir/" -ForegroundColor White
Write-Host ""
