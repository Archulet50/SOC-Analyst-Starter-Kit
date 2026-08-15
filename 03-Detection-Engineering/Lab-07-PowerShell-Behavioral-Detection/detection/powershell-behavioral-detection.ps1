<#
.SYNOPSIS
    Lab 07 - PowerShell Behavioral Detection

.DESCRIPTION
    Evaluates Windows Security Event ID 4688 process-creation telemetry
    for PowerShell execution characteristics.

    This analytic uses weighted behavioral signals rather than treating
    all PowerShell execution as malicious.

.SIGNALS
    EncodedCommand  = +3
    NonInteractive  = +1
    NoProfile       = +1

.DISPOSITION
    Score 0-1 = BASELINE
    Score 2-3 = REVIEW
    Score 4+  = INVESTIGATE

.NOTES
    Security-relevant does not necessarily mean malicious.
    Legitimate administrative tools and automation may produce these
    execution characteristics.

    Lab:    Lab 07 - PowerShell Behavioral Detection
    ATT&CK: T1059.001 - PowerShell
#>

param(
    [int]$Minutes = 30
)

$StartTime = (Get-Date).AddMinutes(-$Minutes)

Write-Host "===== LAB 07 POWERSHELL BEHAVIORAL DETECTION ====="
Write-Host "Window Start : $StartTime"
Write-Host "Window End   : $(Get-Date)"
Write-Host ""

$Events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

$Results = foreach ($Event in $Events) {

    $Message = $Event.Message

    if ($Message -notmatch '(?i)powershell\.exe') {
        continue
    }

    $Score = 0
    $Signals = @()

    if ($Message -match '(?i)-EncodedCommand|-enc\b') {
        $Score += 3
        $Signals += 'EncodedCommand'
    }

    if ($Message -match '(?i)-NonInteractive') {
        $Score += 1
        $Signals += 'NonInteractive'
    }

    if ($Message -match '(?i)-NoProfile') {
        $Score += 1
        $Signals += 'NoProfile'
    }

    $Disposition = if ($Score -ge 4) {
        'INVESTIGATE'
    }
    elseif ($Score -ge 2) {
        'REVIEW'
    }
    else {
        'BASELINE'
    }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        EventID     = $Event.Id
        Score       = $Score
        Signals     = ($Signals -join ', ')
        Disposition = $Disposition
    }
}

if (-not $Results) {
    Write-Host "No PowerShell process-creation events found."
    return
}

$Results |
    Sort-Object TimeCreated |
    Format-Table -AutoSize

Write-Host ""
Write-Host "===== SUMMARY ====="

$Results |
    Group-Object Disposition |
    Sort-Object Name |
    Select-Object Name,Count |
    Format-Table -AutoSize
