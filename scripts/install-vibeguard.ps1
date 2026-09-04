# vibe-audit-ignore download-execution  Reviewed installer must update VibeGuard's own runtime and state.
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$BaselineReviewed,
    [switch]$Uninstall,
    [switch]$RemoveBaseline
)

$ErrorActionPreference = 'Stop'

function Add-ObjectProperty {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value
    )
    if ($null -eq $Object.PSObject.Properties[$Name]) {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
}

function Read-JsonObject {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{}
    }
    $raw = Get-Content -Raw -LiteralPath $Path
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return [pscustomobject]@{}
    }
    return $raw | ConvertFrom-Json
}

function Backup-File {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmssfff'
        Copy-Item -LiteralPath $Path -Destination "$Path.vibeguard-backup-$stamp" -Force
    }
}

function Write-JsonObject {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Backup-File -Path $Path
    $json = $Value | ConvertTo-Json -Depth 30
    [System.IO.File]::WriteAllText($Path, "$json`r`n", [System.Text.UTF8Encoding]::new($false))
}

function Test-IsVibeGuardHook {
    param($Entry)
    if ($null -eq $Entry) { return $false }
    foreach ($hook in @($Entry.hooks)) {
        if ([string]$hook.command -match 'vibeguard-hook\.js') { return $true }
    }
    return $false
}

function Set-HookEntry {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Event,
        [Parameter(Mandatory)][string]$Matcher,
        [Parameter(Mandatory)][string]$HookCommand,
        [Parameter(Mandatory)][string]$StatusMessage
    )
    $settings = Read-JsonObject -Path $Path
    if ($null -eq $settings.hooks) {
        if ($null -eq $settings.PSObject.Properties['hooks']) {
            Add-ObjectProperty -Object $settings -Name 'hooks' -Value ([pscustomobject]@{})
        } else {
            $settings.hooks = [pscustomobject]@{}
        }
    }
    if ($null -eq $settings.hooks.PSObject.Properties[$Event]) {
        Add-ObjectProperty -Object $settings.hooks -Name $Event -Value @()
    }

    $kept = @($settings.hooks.$Event | Where-Object { -not (Test-IsVibeGuardHook -Entry $_) })
    $entry = [pscustomobject]@{
        matcher = $Matcher
        hooks = @([pscustomobject]@{
            type = 'command'
            command = $HookCommand
            timeout = 20
            statusMessage = $StatusMessage
        })
    }
    $settings.hooks.$Event = @($kept + $entry)
    Write-JsonObject -Path $Path -Value $settings
}

function Remove-HookEntries {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $settings = Read-JsonObject -Path $Path
    if ($null -eq $settings.hooks) { return }
    foreach ($event in @('PreToolUse', 'ConfigChange')) {
        if ($null -ne $settings.hooks.PSObject.Properties[$event]) {
            $settings.hooks.$event = @($settings.hooks.$event | Where-Object { -not (Test-IsVibeGuardHook -Entry $_) })
        }
    }
    Write-JsonObject -Path $Path -Value $settings
}

function Get-ProfilePaths {
    $documents = [Environment]::GetFolderPath('MyDocuments')
    return @(
        (Join-Path $documents 'WindowsPowerShell\profile.ps1'),
        (Join-Path $documents 'PowerShell\profile.ps1')
    )
}

function Remove-ProfileBlock {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $content = Get-Content -Raw -LiteralPath $Path
    $updated = [regex]::Replace(
        $content,
        '(?ms)^# >>> VibeGuard global command gate >>>\r?\n.*?^# <<< VibeGuard global command gate <<<\r?\n?',
        ''
    )
    if ($updated -ne $content) {
        Backup-File -Path $Path
        [System.IO.File]::WriteAllText($Path, $updated, [System.Text.UTF8Encoding]::new($false))
    }
}

function Set-ProfileBlock {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$NodePath,
        [Parameter(Mandatory)][string]$GuardCli
    )
    Remove-ProfileBlock -Path $Path
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $nodeQuoted = $NodePath.Replace("'", "''")
    $cliQuoted = $GuardCli.Replace("'", "''")
    $block = @"
# >>> VibeGuard global command gate >>>
function global:vibeguard {
    & '$nodeQuoted' '$cliQuoted' @args
}

if (Get-Module -ListAvailable -Name PSReadLine) {
    Import-Module PSReadLine
    `$script:VibeGuardPreviousValidationHandler = (Get-PSReadLineOption).CommandValidationHandler
    Set-PSReadLineOption -CommandValidationHandler {
        param([System.Management.Automation.Language.CommandAst]`$CommandAst)
        if (`$script:VibeGuardPreviousValidationHandler) {
            & `$script:VibeGuardPreviousValidationHandler `$CommandAst
        }
        `$vibeGuardCommand = `$CommandAst.Extent.Text
        & '$nodeQuoted' '$cliQuoted' check-command --command `$vibeGuardCommand --quiet
        if (`$LASTEXITCODE -eq 3) {
            throw 'VibeGuard paused an unverified install. Run vibeguard approve-command after checking the official source, signature, and hash.'
        }
        if (`$LASTEXITCODE -ne 0) {
            throw 'VibeGuard blocked this command. Run vibeguard check-command --command <command> to see why.'
        }
    }
}
# <<< VibeGuard global command gate <<<
"@
    $existing = if (Test-Path -LiteralPath $Path -PathType Leaf) { Get-Content -Raw -LiteralPath $Path } else { '' }
    Backup-File -Path $Path
    [System.IO.File]::WriteAllText($Path, ($existing.TrimEnd() + "`r`n" + $block), [System.Text.UTF8Encoding]::new($false))
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$localAppData = [Environment]::GetFolderPath('LocalApplicationData')
$guardRoot = Join-Path $localAppData 'VibeAudit\guard'
$claudeSettings = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.claude\settings.json'
$codexHooks = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex\hooks.json'
$baselinePath = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.vibeaudit\agent-baseline.json'

$guardRootFull = [System.IO.Path]::GetFullPath($guardRoot)
$allowedRoot = [System.IO.Path]::GetFullPath((Join-Path $localAppData 'VibeAudit'))
if (-not $guardRootFull.StartsWith($allowedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing unexpected guard path: $guardRootFull"
}

if ($Uninstall) {
    if ($PSCmdlet.ShouldProcess('Claude, Codex, PowerShell profiles, and the local VibeGuard runtime', 'Remove VibeGuard integration')) {
        Remove-HookEntries -Path $claudeSettings
        Remove-HookEntries -Path $codexHooks
        foreach ($profilePath in Get-ProfilePaths) { Remove-ProfileBlock -Path $profilePath }
        if (Test-Path -LiteralPath $guardRootFull) {
            Remove-Item -LiteralPath $guardRootFull -Recurse -Force
        }
        if ($RemoveBaseline -and (Test-Path -LiteralPath $baselinePath -PathType Leaf)) {
            Remove-Item -LiteralPath $baselinePath -Force
        }
        Write-Host 'VibeGuard hooks, profile blocks, and runtime were removed. Timestamped configuration backups remain beside changed files.'
        if (-not $RemoveBaseline) { Write-Host "Reviewed hashes were preserved at $baselinePath." }
    }
    return
}

if (-not $BaselineReviewed -and -not $WhatIfPreference) {
    throw 'Activation requires -BaselineReviewed. This means you manually reviewed the current skills, hooks, and agent settings before trusting their hashes.'
}

$nodeCommand = Get-Command node.exe -ErrorAction Stop
$nodePath = [System.IO.Path]::GetFullPath($nodeCommand.Source)
$sourceGuardCli = Join-Path $projectRoot 'bin\vibeguard.js'
$guardCli = Join-Path $guardRootFull 'bin\vibeguard.js'
$guardHook = Join-Path $guardRootFull 'bin\vibeguard-hook.js'
$hookCommand = '"' + $nodePath + '" "' + $guardHook + '"'

if ($PSCmdlet.ShouldProcess('Claude, Codex, and PowerShell for the current Windows user', 'Install and activate VibeGuard')) {
    & $nodePath $sourceGuardCli preflight
    if ($LASTEXITCODE -eq 4) {
        throw 'VibeGuard found critical or unreadable agent control files. Nothing was installed. Review the reported paths first.'
    }

    New-Item -ItemType Directory -Path (Join-Path $guardRootFull 'bin') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $guardRootFull 'src\guard') -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $projectRoot 'bin\vibeguard.js') -Destination (Join-Path $guardRootFull 'bin\vibeguard.js') -Force
    Copy-Item -LiteralPath (Join-Path $projectRoot 'bin\vibeguard-hook.js') -Destination (Join-Path $guardRootFull 'bin\vibeguard-hook.js') -Force
    Get-ChildItem -LiteralPath (Join-Path $projectRoot 'src\guard') -Filter '*.js' -File |
        Copy-Item -Destination (Join-Path $guardRootFull 'src\guard') -Force
    [System.IO.File]::WriteAllText((Join-Path $guardRootFull 'package.json'), "{`"type`":`"module`"}`r`n", [System.Text.UTF8Encoding]::new($false))

    # Establish trust before enabling hooks. A failed review leaves no active hook behind.
    & $nodePath $guardCli trust-current --i-reviewed-these-files
    if ($LASTEXITCODE -ne 0) {
        throw 'The current agent files did not pass baseline review. Hooks and profiles were not changed.'
    }

    Set-HookEntry -Path $claudeSettings -Event 'PreToolUse' -Matcher '*' -HookCommand $hookCommand -StatusMessage 'VibeGuard checking commands, files, and external tools'
    Set-HookEntry -Path $claudeSettings -Event 'ConfigChange' -Matcher 'user_settings|project_settings|local_settings|skills' -HookCommand $hookCommand -StatusMessage 'VibeGuard checking configuration change'
    Set-HookEntry -Path $codexHooks -Event 'PreToolUse' -Matcher '*' -HookCommand $hookCommand -StatusMessage 'VibeGuard checking commands, files, and external tools'
    foreach ($profilePath in Get-ProfilePaths) {
        Set-ProfileBlock -Path $profilePath -NodePath $nodePath -GuardCli $guardCli
    }

    # Trust only the installer-authored settings changes after all writes succeed.
    & $nodePath $guardCli trust-current --i-reviewed-these-files
    if ($LASTEXITCODE -ne 0) {
        throw 'VibeGuard files were installed, but the reviewed baseline failed. Use the timestamped backups to restore settings before retrying.'
    }

    Write-Host 'VibeGuard is active for Claude tool calls, Codex tool calls, and new interactive PowerShell sessions.'
    Write-Host 'Codex may ask you to trust the new hook hash once. Review the displayed path before accepting.'
}
