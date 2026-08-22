
<#
.SYNOPSIS
    Lab 08 — Windows Multi-Stage Behavioral Correlation

.DESCRIPTION
    Correlates Windows Security Event ID 4688 process-creation telemetry
    to identify multiple discovery behaviors originating from a common
    PowerShell parent process.

    The analytic uses weighted behavioral scoring rather than treating
    individual discovery commands as independently malicious.

    Validation model:

        0-2  = BASELINE
        3-4  = REVIEW
        5+   = INVESTIGATE

.NOTES
    Archuleta Cyber Labs
    SOC Analyst Starter Kit v1.0

    Detection severity identifies activity worthy of investigation.
    It does not, by itself, establish malicious intent.
#>

param(
    [int]$LookbackMinutes = 5
)

$StartTime = (Get-Date).AddMinutes(-$LookbackMinutes)


$Events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = $StartTime
} -ErrorAction SilentlyContinue |
ForEach-Object {

    $xml = [xml]$_.ToXml()
    $data = @{}

    foreach ($item in $xml.Event.EventData.Data) {
        $data[$item.Name] = $item.'#text'
    }    [PSCustomObject]@{
        Time        = $_.TimeCreated
        Account     = $data.SubjectUserName
        Process     = $data.NewProcessName
        ProcessID   = $data.NewProcessId
        CreatorPID  = $data.ProcessId
        Creator     = $data.ParentProcessName
        CommandLine = $data.CommandLine
    }
} |
Where-Object {
    $_.Process -match '\\whoami\.exe$|\\hostname\.exe$|\\ipconfig\.exe$'
}
if (-not $Events) {
    Write-Host "No matching discovery activity detected."
    exit 0
}

$Groups = $Events | Group-Object Account,CreatorPID

foreach ($Group in $Groups) {

    $GroupEvents = @($Group.Group)
    $Commands = @($GroupEvents.CommandLine)

    $Score = 0
    $Behaviors = @()    # Identity discovery
    if ($Commands -match 'whoami\.exe"*$') {
        $Score += 1
        $Behaviors += 'Identity'
    }

    # Group / privilege discovery
    if ($Commands -match 'whoami\.exe"\s+/groups') {
        $Score += 2
        $Behaviors += 'Groups'
    }

    # Host discovery
    if ($Commands -match 'hostname\.exe') {
        $Score += 1
        $Behaviors += 'Host'
    }

    # Network configuration discovery
    if ($Commands -match 'ipconfig\.exe') {
        $Score += 1
        $Behaviors += 'Network'
    }

    $UniqueBehaviors = @($Behaviors | Select-Object -Unique)
    # Multi-behavior correlation bonus
    if ($UniqueBehaviors.Count -ge 3) {
        $Score += 2
    }

    # PowerShell parent bonus
    if ($GroupEvents.Creator -match 'powershell\.exe') {
        $Score += 1
    }

    $Disposition = if ($Score -ge 5) {
        'INVESTIGATE'
    }
    elseif ($Score -ge 3) {
        'REVIEW'
    }
    else {
        'BASELINE'
    }    $FirstEvent = $GroupEvents |
        Sort-Object Time |
        Select-Object -First 1

    $LastEvent = $GroupEvents |
        Sort-Object Time |
        Select-Object -Last 1

    [PSCustomObject]@{
        Account       = $FirstEvent.Account
        CreatorPID    = $FirstEvent.CreatorPID
        Creator       = $FirstEvent.Creator
        FirstObserved = $FirstEvent.Time
        LastObserved  = $LastEvent.Time
        EventCount    = $GroupEvents.Count
        Behaviors     = ($UniqueBehaviors -join ', ')
        Score         = $Score
        Disposition   = $Disposition
    }
}
