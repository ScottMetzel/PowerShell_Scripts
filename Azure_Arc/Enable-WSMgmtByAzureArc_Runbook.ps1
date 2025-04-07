<#
    .SYNOPSIS
    This runbook attempts to enroll all Arc-enabled Servers in Windows Server Management.

    .DESCRIPTION
    This runbook attempts to enroll all Arc-enabled Servers in Windows Server Management.

    It is an iteration and simplification on the previous script, 'Enable-WindowsServerManagementByAzureArc.ps1', and is designed to be run in an Azure Automation Account.

    More information about Windows Server Management Enabled by Azure Arc can be found here:
    https://learn.microsoft.com/en-us/azure/azure-arc/servers/windows-server-management-overview

    This runbook makes state changes at the Azure management plane. It does not make changes within an OS.

    It requires the Az.Accounts, Az.Resources, and PowerShell Utility modules.

    This runbook is provided AS-IS with no warranties or claims it'll work as described. Please review the code and test in a safe environment.
    Executing this runbook is done at your own risk ;) .

    .NOTES
    ===========================================================================
    Created with: 	Microsoft Visual Studio Code
    Created on:   	04/06/2025 2:56 PM
    Created by:   	Scott Metzel
    Organization: 	-
    Filename:     	Enable-WSMgmtByAzureArc_Runbook.ps1
    Comments:     	This runbook builds on Kevin Sullivan's original script, here:
                    https://github.com/kevinsul/arc-ws-sa-enable/blob/main/arc-ws-sa-enable.ps1
    ===========================================================================

    .EXAMPLE
    # Unfiltered
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1

    .OUTPUTS
    System.Collections.ArrayList
#>
#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources, Az.ResourceGraph
[CmdletBinding()]
[OutputType([System.Collections.ArrayList])]
param()
$InformationPreference = 'Continue'
$VerbosePreference = 'Continue'

### BEGIN: Module Import ###
[System.Collections.ArrayList]$ModulesToImport = @(
    'Az.Accounts',
    'Az.Resources',
    'Az.ResourceGraph'
)

[System.Int32]$i = 1
[System.Int32]$ModulesToImportCount = $ModulesToImport.Count

Write-Verbose -Message 'Starting to import PowerShell modules.'
foreach ($Module in $ModulesToImport) {
    $VerbosePreference = 'Continue'
    Write-Verbose -Message "Importing module: '$Module'. Module: '$i' of: '$ModulesToImportCount' modules."
    $VerbosePreference = 'SilentlyContinue'
    Import-Module -Name $Module -Verbose:$false | Out-Null

    $i++
}

Write-Verbose -Message 'Finished importing PowerShell modules.'
$VerbosePreference = 'Continue'
### END: Module Import ###

### BEGIN: Connection Check ###
[System.Boolean]$ConnectedToAzure = $false
Write-Verbose -Message 'Getting current Azure context...'
$GetAzContext = Get-AzContext -ErrorAction SilentlyContinue

if ($GetAzContext) {
    Write-Verbose -Message 'Connected to Azure.'
    [System.Boolean]$ConnectedToAzure = $true
}
else {
    Write-Verbose -Message 'Not connected to Azure... Connecting.'
    Connect-AzAccount -Identity
}

if ($false -eq $ConnectedToAzure) {
    Write-Verbose -Message 'Getting current Azure context again...'
    $GetAzContext = Get-AzContext -ErrorAction SilentlyContinue

    if ($GetAzContext) {
        Write-Verbose -Message 'Now connected to Azure.'
    }
    else {
        Write-Error -Message 'Not connected to Azure. Please connect first and try again.'
        throw
    }
}

### END: Connection Check ###
### BEGIN: ARM URL Capture ###
Write-Verbose -Message 'Getting ARM URL'
[System.String]$AzureResourceManagerURL = $GetAzContext.Environment.ResourceManagerUrl
if ($AzureResourceManagerURL -notin @($null, '')) {
    Write-Verbose -Message "ARM URL is: '$AzureResourceManagerURL'."
}
else {
    Write-Error -Message "ARM URL is empty or null and should start with 'https://management...'. Please connect to Azure and try again."
    throw
}
### END: ARM URL Capture ###

### BEGIN: Load Functions ###
Write-Verbose -Message 'Loading functions.'
function CreateBearerTokenHeaderTable {
    [CmdletBinding(
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(
            Mandatory = $true
        )]
        [Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]$AzContext
    )
    [System.String]$ThisFunctionName = $MyInvocation.MyCommand
    Write-Verbose -Message "Running: '$ThisFunctionName'."

    Write-Verbose -Message 'Creating bearer token object.'
    try {
        $ErrorActionPreference = 'Stop'
        $AzureRmProfileProvider = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
        $ProfileClient = [Microsoft.Azure.Commands.ResourceManager.Common.rmProfileClient]::new($AzureRmProfileProvider)
        $Token = $profileClient.AcquireAccessToken($AzContext.Subscription.TenantId)
        [System.String]$BearerToken = [System.String]::Concat('Bearer ', $Token.AccessToken)
        [System.Collections.Hashtable]$HeaderTable = @{
            'Content-Type'  = 'application/json'
            'Authorization' = $BearerToken
        }

        Write-Verbose -Message 'Outputting bearer token header table.'
        $HeaderTable
    }
    catch {
        $_
        throw
    }
}

function DiscoverMachines {
    [CmdletBinding()]
    [OutputType([System.Array])]
    param (
        [Parameter(
            Mandatory = $false
        )]
        [ValidateRange(1, 1000)]
        [System.Int32]$TakeFirst = 250
    )
    [System.String]$ThisFunctionName = $MyInvocation.MyCommand
    Write-Verbose -Message "Running: '$ThisFunctionName'."

    $ErrorActionPreference = 'Stop'
    [System.String]$ResourceGraphQuery = "resources | where type =~ 'microsoft.hybridcompute/machines' and properties.osType=='windows' and properties.status=='Connected' and properties.licenseProfile.softwareAssurance.softwareAssuranceCustomer != true"
    Write-Verbose -Message 'Getting all Arc-enabled Windows Servers not already enrolled.'

    ## 01.26.2025 - Thanks to Raúl Carboneras Marrero for the extended query.
    [System.String]$ResourceGraphQuery = [System.String]::Concat($ResourceGraphQuery, " | extend osSku = properties.osSku | where osSku !contains '2008' | extend licenseProfile = properties.licenseProfile | extend licenseStatus = tostring(licenseProfile.licenseStatus) | extend licenseChannel = tostring(licenseProfile.licenseChannel) | extend subscriptionStatus = tostring(licenseProfile.productProfile.subscriptionStatus) | extend softwareAssurance = licenseProfile.softwareAssurance | extend softwareAssuranceCustomer = licenseProfile.softwareAssurance.softwareAssuranceCustomer | extend coreCount = toint(properties.detectedProperties.coreCount) | extend logicalCoreCount = toint(properties.detectedProperties.logicalCoreCount)")

    Write-Verbose -Message "Resource Graph Query: '$ResourceGraphQuery'."

    [System.Collections.ArrayList]$MachinesArray = @()
    [System.Int32]$Skip = 0
    try {
        $ErrorActionPreference = 'Stop'
        do {
            Write-Verbose -Message "Taking first: '$TakeFirst'. Skipping: '$Skip'."
            if (0 -eq $Skip) {
                $SearchAzGraph = Search-AzGraph -Query $ResourceGraphQuery -First $TakeFirst
            }
            else {
                $SearchAzGraph = Search-AzGraph -Query $ResourceGraphQuery -First $TakeFirst -Skip $Skip
            }
            [System.Int32]$SearchAzGraphCount = $SearchAzGraph.Count
            Write-Verbose -Message "Search result count: '$SearchAzGraphCount'."
            $SearchAzGraph | Sort-Object -Property Name | ForEach-Object -Process {
                $MachinesArray.Add($_) | Out-Null
            }
            [System.Int32]$Skip = $Skip + $TakeFirst
        } until (
            0 -eq $SearchAzGraph.Count
        )
    }
    catch {
        $_
        throw
    }

    ## 01.16.2025 - TO DO: Change output to hashtable to return ineligible servers
    Write-Verbose -Message 'Outputting array result.'
    $MachinesArray
}

function EnrollMachine {
    [CmdletBinding(
        SupportsShouldProcess,
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Collections.Hashtable])]
    param (
        [PSObject]$Machine,
        [System.Collections.Hashtable]$BearerTokenHeaderTable,
        [ValidatePattern(
            '^(\d{4})(-)(\d{2})(-)(\d{2})($|(-preview)$)'
        )]
        [System.String]$ARMAPIVersion = '2024-07-10',
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet(
            'GET',
            'HEAD',
            'PATCH',
            'POST',
            'PUT'
        )]
        [System.String]$RestMethod = 'PUT',
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet(
            'https://management.azure.com',
            'https://management.usgovcloudapi.net',
            'https://management.microsoftazure.de',
            'https://management.chinacloudapi.cn'
        )]
        [System.String]$ResourceManagerURL = 'https://management.azure.com'
    )
    [System.String]$ThisFunctionName = $MyInvocation.MyCommand
    Write-Verbose -Message "Running: '$ThisFunctionName'."
    [System.String]$MachineSubscriptionID = $Machine.subscriptionID
    [System.String]$MachineName = $Machine.name
    [System.String]$MachineResourceGroupName = $Machine.resourceGroup
    [System.String]$MachineLocation = $Machine.Location
    [System.String]$GETURI = [System.String]::Concat($ResourceManagerURL,'/subscriptions/', $MachineSubscriptionID, '/resourceGroups/', $MachineResourceGroupName, '/providers/Microsoft.HybridCompute/machines/', $MachineName, '?api-version=', $ARMAPIVersion)
    [System.String]$PUTURI = [System.String]::Concat($ResourceManagerURL,'/subscriptions/', $MachineSubscriptionID, '/resourceGroups/', $MachineResourceGroupName, '/providers/Microsoft.HybridCompute/machines/', $MachineName, '/licenseProfiles/default?api-version=', $ARMAPIVersion)

    [System.Uri]$PUTURIObj = [System.Uri]::new( $PUTURI )
    [System.String]$PUTAbsoluteURI = $PUTURIObj.AbsoluteUri

    [System.Uri]$GETURIObj = [System.Uri]::new( $GETURI )
    [System.String]$GETAbsoluteURI = $GETURIObj.AbsoluteUri

    Write-Verbose -Message "GET URI: $GETAbsoluteURI"
    Write-Verbose -Message "PUT URI: $PUTAbsoluteURI"

    [System.String]$ContentType = 'application/json'

    try {
        $ErrorActionPreference = 'Stop'
        Write-Verbose -Message "Getting current state for: '$MachineName'."
        $GetCurrentState = Invoke-RestMethod -Method 'GET' -Uri $GETAbsoluteURI -ContentType $ContentType -Headers $BearerTokenHeaderTable
    }
    catch {
        $_
        throw
    }

    [System.Collections.ArrayList]$CurrentPropertyNames = @()
    Write-Verbose -Message "Getting current properties under 'properties' property."
    ($GetCurrentState.properties | Get-Member | Where-Object -FilterScript { $_.MemberType -eq 'NoteProperty' }).Name | Sort-Object | ForEach-Object -Process {
        $CurrentPropertyNames.Add($_) | Out-Null
    }
    [System.Int32]$CurrentPropertyNamesCount = $CurrentPropertyNames.Count
    if (0 -eq $CurrentPropertyNamesCount) {
        Write-Error -Message "An error occurred while getting current 'properties' properties."
        throw
    }

    if ('softwareAssurance' -notin $CurrentPropertyNames) {
        # If 'softwareAssurance' doesn't exist as a property, neither does the softwareAssuranceCustomer property within, so add the hashtable containing the 'true' value needed to enroll.
        $SACTable = @{
            softwareAssuranceCustomer = $true;
        };
        Write-Verbose -Message "Adding softwareAssurance property and softwareAssurance hashtable set to 'true' as value to object."
        $GetCurrentState.properties | Add-Member -MemberType NoteProperty -Name 'softwareAssurance' -Value $SACTable -TypeName 'System.Management.Automation.PSCustomObject'
    }
    else {
        # If it does, then look for the 'softwareAssuranceCustomer' property within.
        Write-Verbose -Message 'softwareAssurance property already exists.'

        [System.Collections.ArrayList]$CurrentsoftwareAssuranceProperties = @()
        Write-Verbose -Message "Getting current properties under 'softwareAssurance' property."
        ($GetCurrentState.properties.softwareAssurance | Get-Member | Where-Object -FilterScript { $_.MemberType -eq 'NoteProperty' }).Name | Sort-Object | ForEach-Object -Process {
            $CurrentsoftwareAssuranceProperties.Add($_) | Out-Null
        }

        if ('softwareAssuranceCustomer' -notin $CurrentsoftwareAssuranceProperties) {
            # If softwareAssuranceCustomer does not exist, add it with $true as the value
            Write-Verbose -Message "Adding softwareAssuranceCustomer property and 'true' as value to object."
            $GetCurrentState.properties.softwareAssurance | Add-Member -MemberType NoteProperty -Name 'softwareAssuranceCustomer' -Value $true -TypeName 'System.Boolean'
        }
        else {
            # If softwareAssuranceCustomer exists, set it to true
            $GetCurrentState.properties.softwareAssurance.softwareAssuranceCustomer = $true
        }
    }

    # The new properties object shouldn't include those which can't be modified (like 'productProfile') or those which could incorrectly cast the new state (the platform has authority on the 'provisioningState', for instance)
    [System.Collections.ArrayList]$ExcludedPropertyNames = @(
        'cloudMetaData',
        'detectedProperties',
        'errorDetails',
        'lastStatusChange',
        'mssqlDiscovered'
        'osInstallDate',
        'productProfile',
        'provisioningState',
        'status'
    )
    Write-Verbose -Message 'Creating new properties object.'
    $NewPropertiesState = $GetCurrentState.properties | Select-Object -ExcludeProperty $ExcludedPropertyNames

    Write-Verbose -Message "Creating Hashtable for REST API 'PUT' command."
    [System.Collections.Hashtable]$RESTBodyTable = @{
        location   = $MachineLocation;
        properties = $NewPropertiesState
    };

    Write-Verbose -Message 'Building response table...'
    $JSON = $RESTBodyTable | ConvertTo-Json -Depth 50;
    if ($Machine.plan -in @($null, '')) {
        [System.String]$MachinePlan = 'null'
    }
    else {
        [System.String]$MachinePlan = $Machine.plan
    }

    if ($Machine.sku -in @($null, '')) {
        [System.String]$MachineSKU = 'null'
    }
    else {
        [System.String]$MachineSKU = $Machine.sku
    }

    if ($Machine.coreCount -in @($null, '')) {
        [System.Int64]$MachineCoreCount = 0
    }
    else {
        [System.Int64]$MachineCoreCount = $Machine.coreCount
    }

    if ($Machine.logicalCoreCount -in @($null, '')) {
        [System.Int64]$MachineLogicalCoreCount = 0
    }
    else {
        [System.Int64]$MachineLogicalCoreCount = $Machine.logicalCoreCount
    }

    [System.Collections.Hashtable]$ResponseTable = @{
        MachineName      = $MachineName;
        TenantID         = $Machine.tenantId;
        subscriptionID   = $Machine.subscriptionId;
        resourceGroup    = $Machine.resourceGroup;
        location         = $Machine.location;
        ResourceID       = $Machine.id;
        sku              = $MachineSKU;
        plan             = $MachinePlan;
        osSku            = $Machine.osSku;
        licenseStatus    = $Machine.licenseStatus;
        licenseChannel   = $Machine.licenseChannel;
        coreCount        = $MachineCoreCount;
        logicalCoreCount = $MachineLogicalCoreCount;

    }
    try {
        $ErrorActionPreference = 'Continue'
        if ($PSCmdlet.ShouldProcess($MachineName)) {
            Write-Verbose -Message "Creating call to Azure REST API using method: '$RestMethod'."
            Write-Verbose -Message "Enabling Windows Server Management by Azure Arc on Server: '$MachineName'."
            $Response = Invoke-RestMethod -Method $RestMethod -Uri $PUTAbsoluteURI -ContentType $ContentType -Headers $BearerTokenHeaderTable -Body $JSON
            $ResponseTable.Add('ProvisioningState', $Response.Properties.provisioningState)
            $ResponseTable.Add('SoftwareAssurance', $Response.Properties.softwareAssurance)
            $ResponseTable.Add('Result', 'Success')
            $ResponseTable.Add('ErrorMessage', '')
            Write-Verbose -Message "Machine: '$MachineName'. Result: 'Success'."
        }
        else {
            # Putting in a call to Write-Information because Invoke-RestMethod doesn't support 'WhatIf'.
            # This may be short lived once changed to Invoke-AzRestMethod, which does.
            [System.String]$JSONString = [System.Convert]::ToString($JSON)
            Write-Verbose -Message "Would run 'Invoke-RestMethod' with the following parameter values: Method - '$RestMethod', URI - '$PUTAbsoluteURI', ContentType - '$ContentType', Body - '$JSONString'."
            Write-Verbose -Message "Machine: '$MachineName'. Result: 'WhatIf'."
            $ResponseTable.Add('ProvisioningState', 'N/A - WhatIf')
            $ResponseTable.Add('SoftwareAssurance', 'N/A - WhatIf')
            $ResponseTable.Add('Result', 'N/A - WhatIf')
            $ResponseTable.Add('ErrorMessage', 'N/A - WhatIf')
        }
    }
    catch {
        Write-Warning -Message "Machine: '$MachineName'. Result: 'Error'. Continuing."
        $Response
        $ResponseTable.Add('ProvisioningState', $Response.Properties.provisioningState)
        $ResponseTable.Add('SoftwareAssurance', $Response.Properties.softwareAssurance)
        $ResponseTable.Add('Result', 'Error')
        $ResponseTable.Add('ErrorMessage', $_.Errordetails.Message)
    }

    $ResponseTable
}

Write-Verbose -Message 'Finished loading functions.'
### END: Load Functions ###

# Create an array list to collect responses for output at the end.
[System.Collections.ArrayList]$ResponseArray = @()

## Discovery
Write-Verbose -Message 'Getting Bearer token.'
[System.Collections.Hashtable]$BearerTokenHeaderTable = CreateBearerTokenHeaderTable -AzContext $GetAzContext
Write-Verbose -Message 'Will attempt to enroll all Arc-enabled Servers.'

Write-Verbose -Message 'Discovering machines...'
[System.Array]$MachinesArray = DiscoverMachines

[System.Int32]$MachinesArrayCount = $MachinesArray.Count
if (1 -le $MachinesArrayCount) {
    Write-Verbose -Message "Found: '$MachinesArrayCount' eligible Arc-enabled Servers."

    Write-Verbose -Message 'About to start enrolling servers in benefits...'
    [System.Int32]$j = 1
    foreach ($Machine in $MachinesArray) {
        [System.String]$MachineName = $Machine.Name

        Write-Verbose -Message "Working on server: '$MachineName'. Server: '$j' of: '$MachinesArrayCount' servers."
        ## Enrollment
        $Response = EnrollMachine -Machine $Machine -BearerTokenHeaderTable $BearerTokenHeaderTable

        $ResponseArray.Add($Response) | Out-Null

        $j++
    }
}
else {
    Write-Verbose -Message 'Did not find any Arc-enabled servers.'
}

### BEGIN: REPORT ###
if (0 -lt $ResponseArray.Count) {
    Write-Verbose -Message 'Results: '
    $ResponseArray | Select-Object -Property 'MachineName', 'Result', 'SoftwareAssurance', 'ResourceID' | Sort-Object -Property 'ResourceID' | Format-Table -AutoSize

    [System.Int64]$LogicalCoreCount = 0
    $ResponseArray | ForEach-Object -Process {
        if ($_.Result -eq 'Success') {
            [System.Int64]$LogicalCoreCount = $LogicalCoreCount + $_.LogicalCoreCount
        }

    }
    Write-Verbose -Message "Total logical core count enrolled: '$LogicalCoreCount'"
}
else {
    Write-Verbose -Message 'No results to output.'
}
### END: REPORT ###
### END
Write-Verbose -Message 'Exiting.'