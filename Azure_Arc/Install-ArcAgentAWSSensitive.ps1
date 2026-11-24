[CmdletBinding()]
param (
    [System.String]$ServicePrincipalId='',
    [System.String]$ServicePrincipalClientSecret='',
    [System.String]$TENANT_ID = '',
    [System.String]$SUBSCRIPTION_ID = '',
    [System.String]$RESOURCE_GROUP = '',
    [System.String]$ARC_GATEWAY_ID = '',
    [System.String]$FORWARD_PROXY = '',
    [ValidateSet(
        'westcentralus',
        'westus',
        'westus2',
        'westus3',
        IgnoreCase = $true
    )]
    [System.String]$LOCATION = 'westus3',
    [ValidateSet(
        'principal',
        IgnoreCase = $true
    )]
    [System.String]$AUTH_TYPE = 'principal',
    [System.String]$CORRELATION_ID = 'e0f75cfb-3d2d-47c0-bcfc-fe206ce5b6c4',
    [ValidateSet(
        'AzureCloud',
        'AzureUSGovernment',
        'AzureGermanyCloud',
        'AzureChinaCloud',
        IgnoreCase = $true
    )]
    [System.String]$CLOUD = 'AzureCloud'
)

<#
NOTES:
    This script needs to satisfy 4 use cases around Arc.

    1. Service not running - If the Azure Hybrid Instance Metadata service isn't running, try and start it.
    2. Onboarding - Onboard servers regardless of where they are hosted, except for Azure.
    3. AWS & Azure Resource Name Mismatch - If a server is hosted in AWS and the name of the resource in Azure does not match the name of the host (the OS, not the instance ID in AWS), rename it, which requires an offboard/onboard process.
    4. Expired state - If a server is in an Expired state, then 1) remove the resource from Azure and then 2) onboard it.

#>

### START: DEFINE ENVIRONMENT VARIABLES
$env:TENANT_ID = $TENANT_ID;
$env:SUBSCRIPTION_ID = $SUBSCRIPTION_ID;
$env:RESOURCE_GROUP = $RESOURCE_GROUP;
$env:ARC_GATEWAY_ID = $ARC_GATEWAY_ID;
$env:FORWARD_PROXY = $FORWARD_PROXY;
$env:LOCATION = $LOCATION;
$env:AUTH_TYPE = $AUTH_TYPE;
$env:CORRELATION_ID = $CORRELATION_ID;
$env:CLOUD = $CLOUD;
### END: DEFINE ENVIRONMENT VARIABLES

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072;

[System.Boolean]$RunningInAWS = $false
[System.Boolean]$ArcInstalled = $false
[System.Collections.ArrayList]$EC2VendorStrings = @(
    'Amazon EC2',
    'Xen'
)

$InformationPreference = 'Continue'

### START: FUNCTIONS
function Get-InstallArcAgent {
    param (
        [Parameter(Mandatory=$false)]
        [System.Boolean]$IsRunningAWSHosted = $false
    )
    # Download the installation package
    try {
        Write-Information -MessageData 'Downloading the Azure Connected Machine Agent installation package.'
        Invoke-WebRequest -UseBasicParsing -Uri 'https://aka.ms/azcmagent-windows' -TimeoutSec 30 -OutFile "$env:TEMP\install_windows_azcmagent.ps1";
        Write-Information -MessageData 'Successfully downloaded the Azure Connected Machine Agent installation package.'
    }
    catch {
        Write-Information -MessageData 'Failed to download the Azure Connected Machine Agent installation package.'
        $logBody = @{subscriptionId="$env:SUBSCRIPTION_ID";resourceGroup="$env:RESOURCE_GROUP";tenantId="$env:TENANT_ID";location="$env:LOCATION";correlationId="$env:CORRELATION_ID";authType="$env:AUTH_TYPE";operation='onboarding';messageType=$_.FullyQualifiedErrorId;message="$_"; };
        Invoke-WebRequest -UseBasicParsing -Uri 'https://gbl.his.arc.azure.com/log' -Method 'PUT' -Body ($logBody | ConvertTo-Json) | Out-Null;
        Write-Error -Message $_.Exception;
    }

    try {
        # Install the hybrid agent
        if ($IsRunningAWSHosted) {
            Write-Information -MessageData 'Installing the Azure Connected Machine Agent using a proxy since it is hosted in AWS.'
            & "$env:TEMP\install_windows_azcmagent.ps1" -proxy "$env:FORWARD_PROXY";
            if ($LASTEXITCODE -ne 0) {
                exit 1;
            }
        }
        else {
            Write-Information -MessageData 'Installing the Azure Connected Machine Agent.'
            & "$env:TEMP\install_windows_azcmagent.ps1";
            if ($LASTEXITCODE -ne 0) {
                exit 1;
            }
        }

        Write-Information -MessageData 'Successfully installed the Azure Connected Machine Agent.';
    }
    catch {
        Write-Information -MessageData 'Failed to install the Azure Connected Machine Agent.'
        $logBody = @{subscriptionId="$env:SUBSCRIPTION_ID";resourceGroup="$env:RESOURCE_GROUP";tenantId="$env:TENANT_ID";location="$env:LOCATION";correlationId="$env:CORRELATION_ID";authType="$env:AUTH_TYPE";operation='onboarding';messageType=$_.FullyQualifiedErrorId;message="$_"; };
        Invoke-WebRequest -UseBasicParsing -Uri 'https://gbl.his.arc.azure.com/log' -Method 'PUT' -Body ($logBody | ConvertTo-Json) | Out-Null;
        Write-Error -Message $_.Exception;
    }
}

function Connect-ToAzureArc {
    param (
        [Parameter(Mandatory=$false)]
        [System.Boolean]$IsRunningAWSHosted = $false
    )
    [System.String]$AzcmagentPath = [System.String]::Concat($env:ProgramW6432, '\AzureConnectedMachineAgent\azcmagent.exe')
    if ($IsRunningAWSHosted) {
        [System.String]$ComputerName = $env:COMPUTERNAME
        Write-Information -MessageData "Azure Arc resource name will be set to: '$ComputerName'."

        Write-Information -MessageData 'Onboarding server to Azure Arc.'
        & $AzcmagentPath connect --cloud "$env:CLOUD" --tenant-id "$env:TENANT_ID" --service-principal-id "$ServicePrincipalId" --service-principal-secret "$ServicePrincipalClientSecret" --subscription-id "$env:SUBSCRIPTION_ID" --resource-group "$env:RESOURCE_GROUP" --resource-name "$ComputerName" --location "$env:LOCATION" --gateway-id "$env:ARC_GATEWAY_ID" --tags 'Datacenter=OITDC,City=Irvine,StateOrDistrict=CA,CountryOrRegion=US' --correlation-id "$env:CORRELATION_ID";
    }
    else {
        Write-Information -MessageData 'This system is not running in an AWS-hosted environment.'
        & $AzcmagentPath connect --cloud "$env:CLOUD" --tenant-id "$env:TENANT_ID" --service-principal-id "$ServicePrincipalId" --service-principal-secret "$ServicePrincipalClientSecret" --subscription-id "$env:SUBSCRIPTION_ID" --resource-group "$env:RESOURCE_GROUP" --location "$env:LOCATION" --gateway-id "$env:ARC_GATEWAY_ID" --tags 'Datacenter=OITDC,City=Irvine,StateOrDistrict=CA,CountryOrRegion=US' --correlation-id "$env:CORRELATION_ID";
    }
}

function Wait-AzureResourceDeleted {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.String]$Uri,
        [Parameter(Mandatory)]
        [System.Collections.Hashtable]$Headers,
        [System.Int32]$PollIntervalSeconds = 5,
        [System.Int32]$TimeoutSeconds = 300
    )

    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    while ($Stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        try {
            $null = Invoke-WebRequest `
                -Method Get `
                -Uri $Uri `
                -Headers $Headers `
                -ErrorAction Stop

            Write-Host ('Resource still exists ({0:N0}s elapsed).' -f `
                    $Stopwatch.Elapsed.TotalSeconds)
        }
        catch {
            $StatusCode = [int]$_.Exception.Response.StatusCode
            if ($StatusCode -eq 404) {
                $Stopwatch.Stop()
                Write-Host ('Resource deletion confirmed after {0:N1} seconds.' -f `
                        $Stopwatch.Elapsed.TotalSeconds)
                return $true
            }
            throw
        }
        Start-Sleep -Seconds $PollIntervalSeconds
    }

    $Stopwatch.Stop()
    throw "Timed out after $TimeoutSeconds seconds waiting for the Azure resource to disappear."
}
### END: FUNCTIONS

### START: CHECK - ARC INSTALLED
[System.String]$AzcmagentPath = [System.String]::Concat($env:ProgramW6432, '\AzureConnectedMachineAgent\azcmagent.exe')
if (Test-Path -Path $AzcmagentPath -ErrorAction SilentlyContinue) {
    Write-Information -MessageData 'Azure Arc is already installed on this system.';
    [System.Boolean]$ArcInstalled = $true
}
### END: CHECK - ARC INSTALLED

### START: CHECK - AWS HOSTED
[System.Object]$GetComputerSystemProduct = Get-CimInstance -ClassName 'Win32_ComputerSystemProduct' | Select-Object -Property UUID, Name, Vendor
if ($GetComputerSystemProduct.UUID.StartsWith('EC2') -or $GetComputerSystemProduct.Vendor -in $EC2VendorStrings) {
    Write-Information -MessageData 'This system is likely running in AWS.'
    [System.Boolean]$RunningInAWS = $true
}
### END: CHECK - AWS HOSTED

### START: REMEDIATION - STOPPED SERVICE
if ($ArcInstalled) {
    [System.String]$ArcHIMDServiceName = ''
    $GetArcHIMDService = Get-Service -Name $ArcHIMDServiceName
    [System.String]$ArcHIMDServiceStatus = $GetArcHIMDService.Status

    if ($GetArcHIMDService.Status -ne 'Running') {
        Write-Information -MessageData "Azure Arc Hybrid Instance Metadata Service is not running. Current state: '$ArcHIMDServiceStatus'. Will attempt to start."

        try {
            $ErrorActionPreference = 'Stop'
            Start-Service -Name $ArcHIMDServiceName
            Write-Information -MessageData 'Azure Arc Hybrid Instance Metadata Service started.'
        }
        catch {
            $_
            throw
        }
    }
}
### END: REMEDIATION - STOPPED SERVICE

### START: REMEDIATION - CONNECTED CHECK, ONBOARDING, EXPIRED CHECK, & NAME REMEDIATION
# Running in AWS and Azure Arc is already installed
if ($RunningInAWS -and $ArcInstalled) {
    Write-Information -MessageData 'Server is hosted in AWS and Azure Arc is already installed. Checking onboarding status and that resource name matches hostname of server.'
    $GetAzCMAgentStatus = & "$AzcmagentPath" show --json --no-color | ConvertFrom-Json
    [System.String]$LocalResourceName = $GetAzCMAgentStatus.resourceName
    [System.String]$LocalResourceID = $GetAzCMAgentStatus.resourceID

    # Connected Check
    if ($GetAzCMAgentStatus.status -eq 'Connected') {
        Write-Information -MessageData 'Azure Arc agent is connected.'

        # If the resource name does not match the hostname, try to offboard and then onboard from/to Azure
        if ($LocalResourceName -ne $env:COMPUTERNAME) {
            Write-Information -MessageData "Azure Arc resource name: '$LocalResourceName' does not match the hostname: '$env:COMPUTERNAME'. Disconnecting from Azure Arc."

            try {
                & "$AzcmagentPath" disconnect --service-principal-id "$ServicePrincipalId" --service-principal-secret "$ServicePrincipalClientSecret"
            }
            catch {
                Write-Information -MessageData 'Failed to disconnect from Azure Arc.'
                $logBody = @{subscriptionId="$env:SUBSCRIPTION_ID";resourceGroup="$env:RESOURCE_GROUP";tenantId="$env:TENANT_ID";location="$env:LOCATION";correlationId="$env:CORRELATION_ID";authType="$env:AUTH_TYPE";operation='offboarding';messageType=$_.FullyQualifiedErrorId;message="$_"; };
                Invoke-WebRequest -UseBasicParsing -Uri 'https://gbl.his.arc.azure.com/log' -Method 'PUT' -Body ($logBody | ConvertTo-Json) | Out-Null;
                Write-Error -Message $_.Exception;
            }

            Write-Information -MessageData 'Reconnecting to Azure Arc.'
            Connect-ToAzureArc -IsRunningAWSHosted $true
        }
        else {
            Write-Information -MessageData 'Azure Arc resource name matches the hostname. No action required.'
        }
    }
    # Either the server has never been onboarded, or, if there's a Resource ID, it's likely Expired so...
    # Expired Check
    else {
        if ($LocalResourceID -notin @('',$null)) {
            Write-Information -MessageData 'Azuer Arc Agent appears to have a local Resource ID.'
            [System.Boolean]$DeleteAndReOnboard = $true
        }
        else {
            Write-Information -MessageData 'Azure Arc agent likely never connected to Azure. Onboarding to Azure Arc.'
            Connect-ToAzureArc -IsRunningAWSHosted $true
        }
    }
}

# Running in AWS and Azure Arc is not installed
if ($RunningInAWS -and !($ArcInstalled)) {
    Write-Information -MessageData 'Server is hosted in AWS and Azure Arc is not installed. Installing Azure Arc and onboarding the server using its hostname.'

    Get-InstallArcAgent -IsRunningAWSHosted $true

    Write-Information -MessageData 'Onboarding to Azure Arc.'
    Connect-ToAzureArc -IsRunningAWSHosted $true
}

# Not running in AWS and Azure Arc is already installed
if (!($RunningInAWS) -and $ArcInstalled) {
    Write-Information -MessageData 'Server is not hosted in AWS and Azure Arc is already installed. Checking connection status.'

    if ($GetAzCMAgentStatus.status -eq 'Connected') {
        Write-Information -MessageData 'Azure Arc agent is connected. No action required.'
    }
    else {
        if ($LocalResourceID -notin @('',$null)) {
            Write-Information -MessageData 'Azuer Arc Agent appears to have a local Resource ID.'
            [System.Boolean]$DeleteAndReOnboard = $true
        }
        else {
            Write-Information -MessageData 'Azure Arc agent is not connected. Onboarding to Azure Arc.'
            Connect-ToAzureArc -IsRunningAWSHosted $false
        }
    }
}

# Not running in AWS and Azure Arc is not installed
if (!($RunningInAWS) -and !($ArcInstalled)) {
    Write-Information -MessageData 'Server is not hosted in AWS and Azure Arc is not installed. Installing Azure Arc and onboarding the server.'
    Get-InstallArcAgent

    Write-Information -MessageData 'Onboarding server to Azure Arc.'
    Connect-ToAzureArc -IsRunningAWSHosted $false

}

# Arc Installed and Likely Expired
if ($true -eq $DeleteAndReOnboard) {
    Write-Information -MessageData "Azure Arc agent not connected, but appears to have a Resource ID on local record: '$LocalResourceID', which means it's likely expired. Attempting to delete Azure Arc resource and re-onboard."

    # ============================================================
    # 1. Obtain an Azure Resource Manager access token
    # ============================================================

    [System.String]$TokenUri = [System.String]::Concat('https://login.microsoftonline.com/',$TENANT_ID,'/oauth2/v2.0/token')

    [System.Collections.Hashtable]$TokenBody = @{
        client_id     = $ServicePrincipalId
        client_secret = $ServicePrincipalClientSecret
        scope         = 'https://management.azure.com/.default'
        grant_type    = 'client_credentials'
    }

    $TokenResponse = Invoke-RestMethod `
        -Method Post `
        -Uri $TokenUri `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body $TokenBody

    $AccessToken = $TokenResponse.access_token

    if (-not $AccessToken) {
        throw 'Failed to obtain an Azure access token.'
    }

    # ============================================================
    # 2. Construct the Azure Resource Manager DELETE request
    # ============================================================

    [System.String]$ApiVersion = '2026-07-15'
    [System.String]$ResourceURI = [System.String]::Concat('https://management.azure.com',$LocalResourceID)
    [System.String]$ResourceURIWithAPIVersion = [System.String]::Concat($ResourceURI,'?api-version=',$ApiVersion)

    [System.Collections.Hashtable]$Headers = @{
        Authorization = "Bearer $AccessToken"
    }

    # ============================================================
    # 3. Delete the Azure Arc-enabled Server resource
    # ============================================================

    try {
        $Response = Invoke-WebRequest `
            -Method Delete `
            -Uri $ResourceURIWithAPIVersion `
            -Headers $Headers

        Write-Information -MessageData 'Azure Arc machine deletion request submitted.'
        Write-Information -MessageData "HTTP Status: $($Response.StatusCode) $($Response.StatusDescription)"
    }
    catch {
        Write-Error 'Failed to delete Azure Arc machine.'

        if ($_.ErrorDetails.Message) {
            Write-Error $_.ErrorDetails.Message
        }
        else {
            Write-Error $_
        }

        throw
    }

    # Now wait until the resource has been deleted
    try {
        $ErrorActionPreference = 'Stop'
        Wait-AzureResourceDeleted -Uri $ResourceURIWithAPIVersion -Headers $Headers -PollIntervalSeconds 10 -TimeoutSeconds 300
    }
    catch {
        $_
        throw
    }

    # With the resource deleted, now try and re-onboard.
    Write-Information -MessageData 'Onboarding to Azure Arc.'
    if ($RunningInAWS) {
        Connect-ToAzureArc -IsRunningAWSHosted $true
    }
    else {
        Connect-ToAzureArc -IsRunningAWSHosted $false
    }
}
### END: REMEDIATION - CONNECTED CHECK, ONBOARDING, EXPIRED CHECK, & NAME REMEDIATION
Write-Information -MessageData 'Exiting!'