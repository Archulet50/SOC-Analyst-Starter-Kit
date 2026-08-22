<#
Lab 08 — Windows Event Correlation Queries

Purpose:
    Reproduce and investigate the telemetry used by the
    Windows Multi-Stage Behavioral Correlation analytic.

Primary telemetry:
    4688 — Process Creation
    4104 — PowerShell Script Block Logging

Supporting telemetry evaluated:
    4624 — Successful Logon
    4672 — Special Privileges Assigned to New Logon
#>

param(
    [int]$LookbackHours = 24
)

$StartTime = (Get-Date).AddHours(-$LookbackHours)

Write-Host "===== EVENT VOLUME BASELINE ====="

foreach ($EventId in 4624,4672,4688) {

    $Count = @(
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = $EventId
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue
    ).Count

    Write-Host "Security Event $EventId : $Count"
}

$Count4104 = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-PowerShell/Operational'
        Id        = 4104
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue
).Count

Write-Host "PowerShell Event 4104 : $Count4104"

Write-Host "`n===== DISCOVERY PROCESS CREATION — EVENT 4688 ====="

$ProcessEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = $StartTime
} -ErrorAction SilentlyContinue |
ForEach-Object {

    $xml = [xml]$_.ToXml()
    $data = @{}

    foreach ($item in $xml.Event.EventData.Data) {
        $data[$item.Name] = $item.'#text'
    }

    [PSCustomObject]@{
        Time        = $_.TimeCreated
        Account     = $data.SubjectUserName
        NewProcess  = $data.NewProcessName
        ProcessID   = $data.NewProcessId
        CreatorPID  = $data.ProcessId
        Creator     = $data.ParentProcessName
        CommandLine = $data.CommandLine
    }
} |
Where-Object {
    $_.NewProcess -match '\\whoami\.exe$|\\hostname\.exe$|\\ipconfig\.exe$'
}

$ProcessEvents |
Sort-Object Time |
Format-Table Time,Account,NewProcess,ProcessID,CreatorPID -AutoSize
Write-Host "`n===== POWERSHELL SCRIPT BLOCKS — EVENT 4104 ====="

$PowerShellEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PowerShell/Operational'
    Id        = 4104
    StartTime = $StartTime
} -ErrorAction SilentlyContinue |
Where-Object {
    $_.Message -match 'whoami|hostname|ipconfig|LAB08'
}

$PowerShellEvents |
Sort-Object TimeCreated |
Select-Object TimeCreated,Id,Message |
Format-List
Write-Host "`n===== SUPPORTING LOGON TELEMETRY — EVENTS 4624 / 4672 ====="

Write-Host "`nEvent 4624 — Successful Logons"

Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624
    StartTime = $StartTime
} -ErrorAction SilentlyContinue |
Select-Object TimeCreated,Id,Message |
Format-List

Write-Host "`nEvent 4672 — Special Privileges Assigned"

Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4672
    StartTime = $StartTime
} -ErrorAction SilentlyContinue |
Select-Object TimeCreated,Id,Message |
Format-List

Write-Host "`n===== CORRELATION NOTE ====="
Write-Host "Do not correlate events by timestamp alone."
Write-Host "Validate account identity, Logon ID, process relationships,"
Write-Host "session context, and other corroborating attributes."

