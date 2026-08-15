<#
.SYNOPSIS
    Lab 07 - Event ID 4104 PowerShell Script Block Hunt

.DESCRIPTION
    Retrieves PowerShell Operational Event ID 4104 telemetry.

    Script Block Logging can expose PowerShell content that is not
    immediately visible in process-creation telemetry, including
    commands executed through EncodedCommand.

    Use this telemetry together with Event ID 4688 to correlate
    execution context with PowerShell behavior.

.NOTES
    Lab:    Lab 07 - PowerShell Behavioral Detection
    ATT&CK: T1059.001 - PowerShell
#>

param(
    [int]$Minutes = 30,
    [string]$SearchTerm = ''
)

$StartTime = (Get-Date).AddMinutes(-$Minutes)

$Events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PowerShell/Operational'
    Id        = 4104
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

if ($SearchTerm) {
    $Events = $Events | Where-Object {
        $_.Message -match [regex]::Escape($SearchTerm)
    }
}

$Events |
    Select-Object TimeCreated,Id,Message |
    Sort-Object TimeCreated |
    Format-List
