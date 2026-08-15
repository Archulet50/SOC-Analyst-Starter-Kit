<#
.SYNOPSIS
    Lab 07 - Event ID 4688 PowerShell Hunt

.DESCRIPTION
    Retrieves Windows Security Event ID 4688 process-creation events
    involving powershell.exe.

    Event 4688 provides process-level context including:
      - New process name
      - Parent/creator process
      - Process command line
      - Token elevation information
      - User/account context

.NOTES
    Lab:    Lab 07 - PowerShell Behavioral Detection
    ATT&CK: T1059.001 - PowerShell
#>

param(
    [int]$Minutes = 30
)

$StartTime = (Get-Date).AddMinutes(-$Minutes)

Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = $StartTime
} -ErrorAction SilentlyContinue |
Where-Object {
    $_.Message -match '(?i)powershell\.exe'
} |
Select-Object TimeCreated,Id,Message |
Sort-Object TimeCreated |
Format-List
