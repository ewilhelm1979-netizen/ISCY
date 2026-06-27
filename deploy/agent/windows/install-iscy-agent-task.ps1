[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackendUrl,

    [Parameter(Mandatory = $true)]
    [long]$TenantId,

    [string]$BinaryPath = "$env:ProgramFiles\ISCY\iscy-agent.exe",
    [string]$EnrollmentToken = "",
    [string]$MtlsFingerprint = "",
    [int]$IntervalMinutes = 15,
    [string]$TaskName = "ISCY Posture Agent"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    throw "ISCY agent binary not found: $BinaryPath"
}
if ($IntervalMinutes -lt 5) {
    throw "IntervalMinutes must be at least 5."
}

$StateRoot = Join-Path $env:ProgramData "ISCY\Agent"
$StatePath = Join-Path $StateRoot "state.json"
$QueueDir = Join-Path $StateRoot "queue"
New-Item -ItemType Directory -Force -Path $StateRoot, $QueueDir | Out-Null

# Keep state and the persisted secret readable only by SYSTEM and administrators.
& icacls.exe $StateRoot /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Could not harden ACLs for $StateRoot"
}

$CommonArguments = @(
    "--backend-url", $BackendUrl,
    "--tenant-id", $TenantId.ToString(),
    "--state-path", $StatePath,
    "--queue-dir", $QueueDir
)
if ($MtlsFingerprint) {
    $CommonArguments += @("--mtls-fingerprint", $MtlsFingerprint)
}

if ($EnrollmentToken) {
    & $BinaryPath @CommonArguments "--enrollment-token" $EnrollmentToken
    if ($LASTEXITCODE -ne 0) {
        throw "Initial ISCY agent enrollment failed with exit code $LASTEXITCODE"
    }
}
elseif (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
    throw "No persisted agent state exists. Supply -EnrollmentToken for the first installation."
}

function Quote-TaskArgument([string]$Value) {
    return '"' + $Value.Replace('"', '\"') + '"'
}

$TaskArguments = @(
    "--backend-url", (Quote-TaskArgument $BackendUrl),
    "--tenant-id", $TenantId.ToString(),
    "--state-path", (Quote-TaskArgument $StatePath),
    "--queue-dir", (Quote-TaskArgument $QueueDir)
)
if ($MtlsFingerprint) {
    $TaskArguments += @("--mtls-fingerprint", (Quote-TaskArgument $MtlsFingerprint))
}

$Action = New-ScheduledTaskAction -Execute $BinaryPath -Argument ($TaskArguments -join " ")
$Trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
    -Principal $Principal -Settings $Settings -Force | Out-Null

Write-Host "Installed scheduled task '$TaskName'. Agent state: $StatePath"
