#Requires -Version 7.0
#Requires -Modules @{ModuleName='SNMPv3'; ModuleVersion='1.2.1'}
param(
    [Parameter(Mandatory=$true)]
    [System.String]$EntraTenantID,
    [Parameter(Mandatory=$true)]
    [System.String]$TargetIPOrFQDN,
    [Parameter(Mandatory=$true)]
    [System.String]$OID,
    [Parameter(Mandatory=$true)]
    [System.String]$AuthType,
    [Parameter(Mandatory=$true)]
    [System.String]$AuthSecret,
    [Parameter(Mandatory=$true)]
    [System.String]$PrivType,
    [Parameter(Mandatory=$true)]
    [System.String]$PrivSecret,
    [Parameter(Mandatory=$true)]
    [System.String]$KVResourceID,
    [Parameter(Mandatory=$true)]
    [System.String]$KVSecretName,
    [Parameter(Mandatory=$false)]
    [ValidateSet('Walk', 'Get',IgnoreCase=$true)]
    [System.String]$WalkOrGet = 'Get',
    [System.Int32]$SyslogFacility = 21, # 21 = Local5
    [System.Boolean]$AsRunbook = $true
)
### START: FUNCTIONS ###
$VerbosePreference = 'SilentlyContinue'
$InformationPreference = 'Continue'
Write-Verbose -Message 'Loading functions...'
function Write-ToLog {
    param (
        [ValidateSet(
            'Debug',
            'Error',
            'Information',
            'Progress',
            'Success',
            'Verbose',
            'Warning',
            IgnoreCase = $true
        )]
        [psobject]$Stream = 'Verbose',
        [ValidateNotNullOrEmpty()]
        [System.String]$MessageData
    )

    switch ($Stream) {
        'Debug' {
            Write-Debug -Message $MessageData
        }
        'Error' {
            Write-Error -Message $MessageData
        }
        'Information' {
            Write-Information -MessageData $MessageData
        }
        'Progress' {
            Write-Progress -Activity $MessageData
        }
        'Success' {
            Write-Output -InputObject $MessageData
        }
        'Warning' {
            Write-Warning -Message $MessageData
        }
        'Verbose' {
            Write-Verbose -Message $MessageData
        }
    }
}

function Send-LocalSyslog {
    param (
        [string]$Message,
        [int]$Severity = 6, # 6 = Informational, 3 = Error
        [int]$Facility = 21 # 21 = Local5
    )
    # Calculate Priority and Format Message
    $Priority = ($Facility * 8) + $Severity
    $Timestamp = Get-Date -Format 'MMM dd HH:mm:ss'
    $Hostname = $env:COMPUTERNAME
    $SyslogPacket = '<{0}>{1} {2} PowerShell: {3}' -f $Priority, $Timestamp, $Hostname, $Message

    # Send via UDP to Localhost
    $UdpClient = New-Object System.Net.Sockets.UdpClient
    $UdpClient.Connect('127.0.0.1', 514)
    $Bytes = [System.Text.Encoding]::ASCII.GetBytes($SyslogPacket)
    [void]$UdpClient.Send($Bytes, $Bytes.Length)
    $UdpClient.Close()
}

# Example usage:
$Data = Get-Process | Select-Object -First 5 | Out-String
Send-LocalSyslog -Message $Data


Write-ToLog -Stream 'Verbose' -MessageData 'Finished loading functions.'
### END: FUNCTIONS ###
### START: LOAD MODULES ###
$InformationPreference = 'Continue'
$VerbosePreference = 'Continue'
[System.Collections.ArrayList]$ModulesToImport = @(
    'Az.Accounts',
    'Az.KeyVault',
    'Az.Resources',
    'SNMPv3'
)

[System.Int32]$i = 1
[System.Int32]$ModulesToImportCount = $ModulesToImport.Count

Write-ToLog -MessageData 'Importing PowerShell modules.'
$VerbosePreference = 'SilentlyContinue'
foreach ($Module in $ModulesToImport) {
    Write-ToLog -MessageData "Importing module: '$Module'. Module: '$i' of: '$ModulesToImportCount' modules."
    Import-Module -Name $Module -Verbose:$false | Out-Null

    $i++
}
$VerbosePreference = 'Continue'
Write-ToLog -MessageData 'Finished importing PowerShell modules.'
### END: LOAD MODULES ###
### START: CONNECT TO AZURE ###
# Ensures you do not inherit an AzContext in your runbook
Write-ToLog -MessageData 'Disabling Azure context autosave.'
Disable-AzContextAutosave -Scope Process

[System.Collections.ArrayList]$KVRIDArray = $KVResourceID.Split('/')

[System.String]$KVSubscriptionID = $KVRIDArray[2]
[System.String]$KVResourceGroupName = $KVRIDArray[4]
[System.String]$KVName = $KVRIDArray[-1]

[System.String]$FirstAzTenantID = $EntraTenantID
[System.String]$FirstAzSubscriptionID = $KVSubscriptionID

if ($true -eq $AsRunbook) {
    [System.String]$AzConnectMessage = [System.String]::Concat('Connecting to Azure using a System-Assigned Managed Identity to Tenant ID: ''', $FirstAzTenantID, ''' and Azure Subscription ID: ''', $FirstAzSubscriptionID, '''.')
    Write-ToLog -MessageData $AzConnectMessage
    try {
        $ErrorActionPreference = 'Stop'
        Connect-AzAccount -Environment 'AzureCloud' -Tenant $FirstAzTenantID -Subscription $FirstAzSubscriptionID -Identity -WarningAction SilentlyContinue
    }
    catch {
        Write-Error -Message $_
    }
}
else {
    [System.String]$AzConnectMessage = [System.String]::Concat('Connecting to Azure using user credentials to Tenant ID: ''', $FirstAzTenantID, ''' and Azure Subscription ID: ''', $FirstAzSubscriptionID, '''.')
    Write-ToLog -MessageData $AzConnectMessage
    try {
        $ErrorActionPreference = 'Stop'
        Connect-AzAccount -Environment 'AzureCloud' -Tenant $FirstAzTenantID -Subscription $FirstAzSubscriptionID -WarningAction SilentlyContinue
    }
    catch {
        Write-Error -Message $_
    }
}
### END: CONNECT TO AZURE ###
### START: TEST CONNECTION ###
# Test Connection to the target device
try {
    $ErrorActionPreference = 'Stop'
    Test-Connection -ComputerName $TargetIPOrFQDN -Count 1 -ErrorAction Stop | Out-Null
}
catch {
    Write-Error "Unable to reach target device '$TargetIPOrFQDN'. Please check the network connectivity and try again."
    throw
}
### END: TEST CONNECTION ###
### START: RETRIEVE SNMPv3 CREDENTIALS ###
try {
    $ErrorActionPreference = 'Stop'
    Write-ToLog -MessageData "Retrieving Key Vault in resource group '$KVResourceGroupName' named: '$KVName'."
    $GetKeyVault = Get-AzKeyVault -ResourceGroupName $KVResourceGroupName -VaultName $KVName

    if ($GetKeyVault) {
        Write-ToLog -MessageData "Successfully retrieved Key Vault in resource group '$KVResourceGroupName' named: '$KVName'."
    }
    else {
        Write-Error "Key Vault not found in resource group '$KVResourceGroupName' named: '$KVName'. Please check the Key Vault and try again."
    }
}
catch {
    Write-Error "Unable to retrieve Key Vault in resource group '$KVResourceGroupName' named: '$KVName'. Please check the Key Vault and try again."
    throw
}

try {
    $ErrorActionPreference = 'Stop'
    Write-ToLog -MessageData "Retrieving SNMPv3 credentials from Key Vault '$KVName'."
    $GetKVSecret = Get-AzKeyVaultSecret -VaultName $KVName -Name 'SNMPv3Credentials' -ErrorAction Stop
    $SNMPv3Username = $GetKVSecret.Name
    $SNMPv3Password = $GetKVSecret.SecretValueText
}
catch {
    Write-Error "Unable to retrieve SNMPv3 credentials from Key Vault '$KVName'. Please check the Key Vault and try again."
    exit 1
}
### END: RETRIEVE SNMPv3 CREDENTIALS ###
### START: RETRIEVE SNMP METRICS ###
# Note: Thanks to: https://github.com/lahell/SNMPv3
switch ($WalkOrGet) {
    'Walk' {
        $WalkRequest = @{
            UserName   = $SNMPv3Username
            Target     = $TargetIPOrFQDN
            OID        = $OID
            AuthType   = $AuthType
            AuthSecret = $SNMPv3Password
            PrivType   = $PrivType
            PrivSecret = $PrivSecret
            Context    = 'da761cfc8c94d3aceef4f60f049105ba'
        }

        $GetSNMPv3Metrics = Invoke-SNMPv3Walk @WalkRequest | Format-Table -AutoSize
    }
    'Get' {
        $GetRequest = @{
            UserName   = $SNMPv3Username
            Target     = $TargetIPOrFQDN
            OID        = $OID
            AuthType   = $AuthType
            AuthSecret = $SNMPv3Password
            PrivType   = $PrivType
            PrivSecret = $PrivSecret
            Context    = 'da761cfc8c94d3aceef4f60f049105ba'
        }

        $GetSNMPv3Metrics = Invoke-SNMPv3Get @GetRequest | Format-Table -AutoSize
    }
}
### END: RETRIEVE SNMP METRICS ###
### START: SEND SNMP METRICS TO LOCAL SYSLOG ###
$GetSNMPv3Metrics | ForEach-Object -Process {
    $Message = $_ | Out-String
    Send-LocalSyslog -Message $Message -Severity 6 -Facility 21
}
### END: SEND SNMP METRICS TO LOCAL SYSLOG ###
Write-ToLog -MessageData 'Exiting!'