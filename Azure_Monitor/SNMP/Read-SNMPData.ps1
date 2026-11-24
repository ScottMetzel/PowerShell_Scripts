param (
    [System.String]$IP = '10.16.1.4',
    [System.String]$OID = '1.3.6.1.2.1.1.1.0',
    [System.String]$Community = 'DOUGHNUTS'
)

function Write-Syslog {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [object]$InputObject,
        [ValidateSet(
            'emerg',
            'alert',
            'crit',
            'err',
            'warning',
            'notice',
            'info',
            'debug'
        )]
        [string]$Severity = 'info',
        [ValidateSet(
            'user',
            'local0',
            'local1',
            'local2',
            'local3',
            'local4',
            'local5',
            'local6',
            'local7'
        )]
        [string]$Facility = 'local0',
        [string]$Tag = 'PowerShell',
        [switch]$AsJson
    )

    process {
        # Convert the PowerShell object into a loggable string.
        if ($AsJson) {
            $Message = $InputObject | ConvertTo-Json -Compress -Depth 10
        }
        elseif ($InputObject -is [string]) {
            $Message = $InputObject
        }
        else {
            $Message = $InputObject | Out-String
            $Message = $Message.Trim()
        }

        # Remove embedded line breaks so one object becomes one
        # syslog event.
        $Message = $Message -replace '\r?\n', ' '

        # Linux logger priority format:
        # facility.severity
        $FacilityAndSeverity = "$Facility.$Severity"

        & /usr/bin/logger -p $FacilityAndSeverity -t $Tag $Message

        if ($LASTEXITCODE -ne 0) {
            throw "logger failed with exit code $LASTEXITCODE"
        }
    }
}

$GetSNMPData = Get-SNMPData -IP $IP -OID $OID -Community $Community

$GetSNMPData | Add-Member -MemberType NoteProperty -Name 'IP' -Value $IP

[System.String]$GetSNMPDataJSON = $GetSNMPData | ConvertTo-Json -Depth 20
$GetSNMPDataJSON | ForEach-Object -Process {
    $Message = $_ | Out-String
    Write-Syslog -InputObject $Message -Severity 'info' -Facility 'local6'
}