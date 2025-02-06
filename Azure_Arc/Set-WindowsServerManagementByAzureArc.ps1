<#
    .SYNOPSIS
    This script attempts to enroll or de-enroll Arc-enabled Servers in Windows Server Management.

    .DESCRIPTION
    This script attempts to enroll or de-enroll Arc-enabled Servers in Windows Server Management.

    More information about Windows Server Management Enabled by Azure Arc can be found here:
    https://learn.microsoft.com/en-us/azure/azure-arc/servers/windows-server-management-overview

    This script makes state changes at the Azure management plane. It does not make changes within an OS.

    It requires the Az.Accounts, Az.Resources, and PowerShell Utility modules.

    This script is provided AS-IS with no warranties or claims it'll work as described. Please review the code and test in a safe environment.
    Executing this script is done at your own risk ;) .

    .NOTES
    ===========================================================================
    Created with: 	Microsoft Visual Studio Code
    Created on:   	02/04/2025 10:33 PM
    Created by:   	Scott Metzel
    Organization: 	-
    Filename:     	Set-WindowsServerManagementByAzureArc.ps1
    Comments:     	This script builds on Kevin Sullivan's original script, here:
                    https://github.com/kevinsul/arc-ws-sa-enable/blob/main/arc-ws-sa-enable.ps1
    ===========================================================================

    .PARAMETER TenantIDs
    Supply ID(s) of an Entra ID tenant. Sets the script to run at an Azure environment scope across all subscriptions attached to the tenant.

    .PARAMETER ManagementGroupIDs
    Supply ID(s) of Management Groups in your organization. Sets the script to search for matching subscriptions under the supplied Management Group IDs.

    .PARAMETER SubscriptionIDs
    Supply Azure subscription ID(s). Sets the script to run at an Azure subscription scope.

    .PARAMETER ResourceGroupNames
    Supply the name of resource group(s) in the current Azure contxt. Sets the script to run at an Azure resource group scope.

    .PARAMETER MachineNames
    Supply (a) machine name(s). Sets the script to run at a subscription scope, but looks for matching machine names in the subscription.
    When paired with the 'ResourceGroupNames' parameter, only machines discovered in the supplied resource groups will be enrolled.

    .PARAMETER ExcludeMachineResourceIDs
    Supply Resource ID(s) of (a) machine(s) to exclude them from being enrolled.

    .PARAMETER ReportDirectoryPath
    Supply a valid existing directory to create a report in.

    .PARAMETER ReportOnly
    Sets the script to only run a report. Does not enroll servers, but will output a report.

    .PARAMETER TakeFirst
    Sets discovery to break up the discovery loop into smaller batches.

    .EXAMPLE
    # Unfiltered
    PS> Connect-AzAccount
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1

    .EXAMPLE
    # Unfiltered with Reporting
    PS> Connect-AzAccount
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ReportDirectoryPath 'C:\Temp'

    .EXAMPLE
    # Unfiltered with Reporting Only
    PS> Connect-AzAccount
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ReportDirectoryPath 'C:\Temp' -ReportOnly
    .EXAMPLE
    # Tenant filtering with WhatIf
    PS> Connect-AzAccount -TenantID '00000000-0000-0000-0000-000000000000'
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -WhatIf

    .EXAMPLE
    # Multiple specific Entra ID tenants
    PS> [System.String]$TenantID1 = '00000000-0000-0000-0000-000000000000'
    PS> [System.String]$TenantID2 = '11111111-1111-1111-1111-111111111111'
    PS> Connect-AzAccount -TenantID $TenantID1
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -TenantIDs $TenantID1, $TenantID2

    .EXAMPLE
    # Management Group filtering
    PS> Connect-AzAccount -ManagementGroupIDs 'MyOrg_Production'
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1

    .EXAMPLE
    # Multiple Management Group IDs
    PS> Connect-AzAccount -ManagementGroupIDs 'MyOrg_Development','MyOrg_Production'
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1

    .EXAMPLE
    # Subscription filtering
    PS> Connect-AzAccount
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -SubscriptionIDs '00000000-0000-0000-0000-000000000000'

    .EXAMPLE
    # Multiple subscription IDs
    PS> Connect-AzAccount
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -SubscriptionIDs '00000000-0000-0000-0000-000000000000', '11111111-1111-1111-1111-111111111111'

    .EXAMPLE
    # Resource Group filtering
    PS> Connect-AzAccount
    PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01'

    .EXAMPLE
    # Multiple resource groups
    PS> Connect-AzAccount
    PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01', 'Prod-RG-Arc-02'

    .EXAMPLE
    # Machine filtering with resource group filtering
    PS> Connect-AzAccount
    PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01', 'Prod-RG-Arc-02' -MachineNames 'Server1'

    .EXAMPLE
    # Multiple machines in multiple resource groups
    PS> Connect-AzAccount
    PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01', 'Prod-RG-Arc-02' -MachineNames 'Server1', 'Server2'

    .EXAMPLE
    # Multiple machines in a single resource group
    PS> Connect-AzAccount
    PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01' -MachineNames 'Server1', 'Server2'

    .EXAMPLE
    # Multiple machines, which can span resource groups
    PS> Connect-AzAccount
    PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -MachineNames 'Server1', 'Server2'

    .EXAMPLE
    # Exclude specific machine(s)
    PS> Connect-AzAccount
    PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -MachineNames 'Server1', 'Server2' -ExcludeMachineResourceIDs '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Prod-RG-3TierApp-01/providers/Microsoft.HybridCompute/machines/Server3'

    .OUTPUTS
    System.Collections.ArrayList
#>
#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources
[CmdletBinding(
    DefaultParameterSetName = '__AllParameterSets',
    SupportsShouldProcess,
    ConfirmImpact = 'Low'
)]
[OutputType([System.Collections.ArrayList])]
param(
    [Parameter(
        Mandatory = $false
    )]
    [ValidateSet(
        'Enable',
        'Disable'
    )]
    [System.String]$EnrollmentState = 'Enable',
    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'TenantIDs'
    )]
    [System.String[]]$TenantIDs,
    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'ManagementGroupIDs'
    )]
    [System.String[]]$ManagementGroupIDs,
    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'Subscriptions'
    )]
    [ValidateScript(
        {
            [System.Guid]::TryParse($_, $([ref][System.Guid]::Empty))
        }
    )]
    [System.String[]]$SubscriptionIDs,
    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'ResourceGroupOrMachines'
    )]
    [System.String[]]$ResourceGroupNames,
    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'ResourceGroupOrMachines'
    )]
    [System.String[]]$MachineNames,
    [Parameter(
        Mandatory = $false
    )]
    [System.String[]]$ExcludeMachineResourceIDs,
    [Parameter(
        Mandatory = $false
    )]
    [ValidateLength(2, 260)]
    [System.String]$ReportDirectoryPath,
    [Parameter(
        Mandatory = $false
    )]
    [switch]$ReportOnly,
    [Parameter(
        Mandatory = $false
    )]
    [ValidateRange(1, 1000)]
    [System.Int32]$TakeFirst = 250
)
$InformationPreference = 'Continue'
[System.String]$ScriptName = $MyInvocation.MyCommand.Name
[System.String]$ScriptNameNoExt = $ScriptName.Split('.')[0]
[System.String]$Now = Get-Date -Format FileDateTimeUniversal

Write-Information -MessageData "Starting: '$ScriptName'."

### BEGIN: Connection Check ###
Write-Information -MessageData 'Getting current Azure context...'
$GetAzContext = Get-AzContext

if ($GetAzContext) {
    Write-Information -MessageData 'Connected to Azure.'
}
else {
    Write-Error -Message 'Not connected to Azure. Please connect first and try again.'
    throw
}
### END: Connection Check ###
### BEGIN: ARM URL Capture ###
Write-Information -MessageData "Getting ARM URL"
[System.String]$AzureResourceManagerURL = $GetAzContext.Environment.ResourceManagerUrl
if ($AzureResourceManagerURL -notin @($null, '')) {
    Write-Information -MessageData "ARM URL is: '$AzureResourceManagerURL'."
}
else {
    Write-Error -Message "ARM URL is empty or null and should start with 'https://management...'. Please connect to Azure and try again."
    throw
}
### END: ARM URL Capture ###
### BEGIN: Report Setup ###
if ($PSBoundParameters.ContainsKey('ReportDirectoryPath')) {
    Write-Information -MessageData 'A report directory was specified.'

    Write-Information -MessageData 'Normalizing provided parameter value.'
    try {
        $ErrorActionPreference = 'Stop'
        $ReportDirectoryPathNET = [System.IO.DirectoryInfo]::new($ReportDirectoryPath)

        [System.String]$ReportDirectoryPathNormalized = [System.String]::Concat($ReportDirectoryPathNET.Parent, $ReportDirectoryPathNET.BaseName)
    }
    catch {
        throw
    }

    try {
        $ErrorActionPreference = 'Stop'
        if (Test-Path -Path $ReportDirectoryPathNormalized -IsValid) {
            Write-Information -MessageData 'Report directory synatx is valid.'

            if (Test-Path -Path $ReportDirectoryPathNormalized -PathType 'Container') {
                Write-Information -MessageData "Report directory path: '$ReportDirectoryPathNormalized' is valid."
            }
            else {
                Write-Warning -Message "Report directory path: '$ReportDirectoryPathNormalized' is not a directory."
                throw
            }
        }
        else {
            Write-Warning -Message "Report directory syntax: '$ReportDirectoryPathNormalized' is invalid."
            throw
        }
    }
    catch {
        $_
    }
}
### END: Report Setup ###

function CreateBearerTokenHeaderTable {
    [CmdletBinding(
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Collections.Hashtable])]
    param ()
    [System.String]$ThisFunctionName = $MyInvocation.MyCommand
    Write-Information -MessageData "Running: '$ThisFunctionName'."

    Write-Information -MessageData 'Creating bearer token object.'
    try {
        $ErrorActionPreference = 'Stop'
        $profile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
        $ProfileClient = [Microsoft.Azure.Commands.ResourceManager.Common.rmProfileClient]::new($profile)
        $Token = $profileClient.AcquireAccessToken($GetAzContext.Subscription.TenantId)
        [System.String]$BearerToken = [System.String]::Concat('Bearer ', $Token.AccessToken)
        [System.Collections.Hashtable]$HeaderTable = @{
            'Content-Type'  = 'application/json'
            'Authorization' = $BearerToken
        }

        Write-Information -MessageData 'Outputting bearer token header table.'
        $HeaderTable
    }
    catch {
        $_
        throw
    }
}

function DiscoverMachines {
    [CmdletBinding(
        DefaultParameterSetName = '__AllParameterSets',
        SupportsShouldProcess,
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Array])]
    param (
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet(
            'Enable',
            'Disable'
        )]
        [System.String]$EnrollmentState = 'Enable',
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'TenantIDs'
        )]
        [System.String[]]$TenantIDs,
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'ManagementGroupIDs'
        )]
        [System.String[]]$ManagementGroupIDs,
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'Subscriptions'
        )]
        [System.String[]]$SubscriptionIDs,
        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'ResourceGroupOrMachines'
        )]
        [System.String[]]$ResourceGroupNames,
        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'ResourceGroupOrMachines'
        )]
        [System.String[]]$MachineNames,
        [Parameter(
            Mandatory = $false
        )]
        [ValidateRange(1, 1000)]
        [System.Int32]$TakeFirst = 250
    )
    [System.String]$ThisFunctionName = $MyInvocation.MyCommand
    Write-Information -MessageData "Running: '$ThisFunctionName'."

    $ErrorActionPreference = 'Stop'
    [System.String]$ResourceGraphQuery = "resources | where type =~ 'microsoft.hybridcompute/machines' and properties.osType=='windows' and properties.status=='Connected' and properties.licenseProfile.softwareAssurance.softwareAssuranceCustomer"
    switch ($EnrollmentState) {
        'Enable' {
            Write-Information -MessageData "Enrollment state is set to: '$EnrollmentState'."
            [System.String]$ResourceGraphQuery = [System.String]::Concat($ResourceGraphQuery, ' != true')
        }
        'Disable' {
            Write-Information -MessageData "Enrollment state is set to: '$EnrollmentState'."
            [System.String]$ResourceGraphQuery = [System.String]::Concat($ResourceGraphQuery, ' == true')
        }
    }
    Write-Verbose -Message "Resource Graph Query is now: '$ResourceGraphQuery'."

    switch ($PSCmdlet.ParameterSetName) {
        '__AllParameterSets' {
            Write-Information -MessageData 'Getting all Arc-enabled Windows Servers not already enrolled.'
        }
        'TenantIDs' {
            if (1 -lt $TenantIDs.Count) {
                [System.String]$TenantIDsString = ($TenantIDs | ForEach-Object { "'$_'" }) -join ','
            }
            else {
                [System.String]$TenantIDsString = [System.String]::Concat('''', $TenantIDs, '''')
            }

            Write-Information -MessageData "Getting all Arc-enabled Windows Servers not already enrolled across all subscriptions in tenants: $TenantIDsString."
            [System.String]$TenantIDsQueryArrayString = [System.String]::Concat('(', $TenantIDsString , ')')
            [System.String]$ResourceGraphQuery = [System.String]::Concat($ResourceGraphQuery, ' and tenantId in', $TenantIDsQueryArrayString)
        }
        'Subscriptions' {
            if (1 -lt $SubscriptionIDs.Count) {
                [System.String]$SubscriptionIDsString = ($SubscriptionIDs | ForEach-Object { "'$_'" }) -join ','
            }
            else {
                [System.String]$SubscriptionIDsString = [System.String]::Concat('''', $SubscriptionIDs, '''')
            }

            Write-Information -MessageData "Getting all Arc-enabled Windows Servers not already enrolled in subscriptions: '$SubscriptionIDsString'."
            [System.String]$SubscriptionIDsQueryArrayString = [System.String]::Concat('(', $SubscriptionIDsString , ')')
            [System.String]$ResourceGraphQuery = [System.String]::Concat($ResourceGraphQuery, ' and subscriptionId in ', $SubscriptionIDsQueryArrayString)
        }
        'ResourceGroupOrMachines' {
            Write-Information -MessageData 'Getting context.'
            $GetAzContext = Get-AzContext
            [System.String]$AzSubscriptionName = $GetAzContext.Subscription.Name
            [System.String]$AzSubscriptionID = $GetAzContext.Subscription.Id
            if ($PSBoundParameters.ContainsKey('ResourceGroupNames') -and (!($PSBoundParameters.ContainsKey('MachineNames')))) {
                Write-Information -MessageData "Getting all Arc-enabled Windows Servers not already enrolled in subscription: '$AzSubscriptionName' in resource group: '$ResourceGroupNames' ."
                if (1 -lt $MachineNames.Count) {
                    [System.String]$ResourceGroupNamesString = ($ResourceGroupNames | ForEach-Object { "'$_'" }) -join ','
                }
                else {
                    [System.String]$ResourceGroupNamesString = [System.String]::Concat('''', $ResourceGroupNames, '''')
                }
                [System.String]$ResourceGroupNamesQueryArrayString = [System.String]::Concat('(', $ResourceGroupNamesString , ')')
                [System.String]$ResourceGraphQuery = [System.String]::Concat($ResourceGraphQuery, " and subscriptionId == '", $AzSubscriptionID, "' and resourceGroup in~ ", $ResourceGroupNamesQueryArrayString)
            }
            elseif ((!($PSBoundParameters.ContainsKey('ResourceGroupNames'))) -and $PSBoundParameters.ContainsKey('MachineNames')) {
                Write-Information -MessageData "Getting Arc-enabled Windows Servers not already enrolled across resource groups in subscription: '$AzSubscriptionName'."
                if (1 -lt $MachineNames.Count) {
                    [System.String]$MachineNamesString = ($MachineNames | ForEach-Object { "'$_'" }) -join ','
                }
                else {
                    [System.String]$MachineNamesString = [System.String]::Concat('''', $MachineNames, '''')
                }
                [System.String]$MachineNameQueryArrayString = [System.String]::Concat('(', $MachineNamesString , ')')
                [System.String]$ResourceGraphQuery = [System.String]::Concat($ResourceGraphQuery, " and subscriptionId == '", $AzSubscriptionID, "' and name in~ ", $MachineNameQueryArrayString)
            }
            else {
                Write-Information -MessageData "Getting specific Arc-enabled Windows Servers not already enrolled in resource groups: '$ResourceGroupNames' in subscription: '$AzSubscriptionName'."
                if (1 -lt $MachineNames.Count) {
                    [System.String]$ResourceGroupNamesString = ($ResourceGroupNames | ForEach-Object { "'$_'" }) -join ','
                }
                else {
                    [System.String]$ResourceGroupNamesString = [System.String]::Concat('''', $ResourceGroupNames, '''')
                }
                [System.String]$ResourceGroupNamesQueryArrayString = [System.String]::Concat('(', $ResourceGroupNamesString , ')')

                if (1 -lt $MachineNames.Count) {
                    [System.String]$MachineNamesString = ($MachineNames | ForEach-Object { "'$_'" }) -join ','
                }
                else {
                    [System.String]$MachineNamesString = [System.String]::Concat('''', $MachineNames, '''')
                }
                [System.String]$MachineNameQueryArrayString = [System.String]::Concat('(', $MachineNamesString , ')')
                [System.String]$ResourceGraphQuery = [System.String]::Concat($ResourceGraphQuery, " and subscriptionId == '", $AzSubscriptionID, "' and resourceGroup in~ ", $ResourceGroupNamesQueryArrayString, ' and name in~ ', $MachineNameQueryArrayString)
            }
        }
    }

    ## 01.26.2025 - Thanks to Raúl Carboneras Marrero for the extended query.
    [System.String]$ResourceGraphQuery = [System.String]::Concat($ResourceGraphQuery, " | extend osSku = properties.osSku | where osSku !contains '2008' | extend licenseProfile = properties.licenseProfile | extend licenseStatus = tostring(licenseProfile.licenseStatus) | extend licenseChannel = tostring(licenseProfile.licenseChannel) | extend subscriptionStatus = tostring(licenseProfile.productProfile.subscriptionStatus) | extend softwareAssurance = licenseProfile.softwareAssurance | extend softwareAssuranceCustomer = licenseProfile.softwareAssurance.softwareAssuranceCustomer | extend coreCount = toint(properties.detectedProperties.coreCount) | extend logicalCoreCount = toint(properties.detectedProperties.logicalCoreCount)")

    switch ($PSCmdlet.ParameterSetName) {
        'ManagementGroupIDs' {
            if (1 -lt $ManagementGroupIDs.Count) {
                [System.String]$ManagementGroupIDsString = ($ManagementGroupIDs | ForEach-Object { "'$_'" }) -join ','
            }
            else {
                [System.String]$ManagementGroupIDsString = [System.String]::Concat('''', $ManagementGroupIDs, '''')
            }

            Write-Information -MessageData "Getting all Arc-enabled Windows Servers not already enrolled in Management Groups: '$ManagementGroupIDsString'."
            [System.String]$ManagementGroupIDsQueryArrayString = [System.String]::Concat('(', $ManagementGroupIDsString , ')')
            [System.String]$ResourceGraphQuery = [System.String]::Concat($ResourceGraphQuery, "| join kind=inner (resourcecontainers | where type == 'microsoft.resources/subscriptions' | mv-expand managementGroupAncestorsTree = properties.managementGroupAncestorsChain | where managementGroupAncestorsTree.name in ", $ManagementGroupIDsQueryArrayString,') on subscriptionId')
        }
    }
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
    Write-Information -MessageData 'Outputting array result.'
    $MachinesArray
}

function SetEnrollmentState {
    [CmdletBinding(
        SupportsShouldProcess,
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Collections.Hashtable])]
    param (
        [PSObject]$Machine,
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet(
            'Enable',
            'Disable'
        )]
        [System.String]$EnrollmentState = 'Enable',
        [System.Collections.Hashtable]$BearerTokenHeaderTable,
        [ValidatePattern(
            '^(\d{4})(-)(\d{2})(-)(\d{2})($|(-preview)$)'
        )]
        [System.String]$ARMAPIVersion = '2024-07-10',
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet(
            'https://management.azure.com/',
            'https://management.usgovcloudapi.net/',
            'https://management.microsoftazure.de/',
            'https://management.chinacloudapi.cn/'
        )]
        [System.String]$ResourceManagerURL = 'https://management.azure.com/'
    )
    [System.String]$ThisFunctionName = $MyInvocation.MyCommand
    Write-Information -MessageData "Running: '$ThisFunctionName'."
    [System.Array]$ResourceIDArray = $Machine.ResourceId -split '/'
    [System.String]$MachineSubscriptionID = $Machine.subscriptionID
    [System.String]$MachineName = $Machine.Name
    [System.String]$MachineResourceGroupName = $ResourceIDArray[4]
    [System.String]$MachineLocation = $Machine.Location
    [System.String]$URIString = [System.String]::Concat($ResourceManagerURL,'subscriptions/', $MachineSubscriptionID, '/resourceGroups/', $MachineResourceGroupName, '/providers/Microsoft.HybridCompute/machines/', $MachineName, '/licenseProfiles/default?api-version=', $ARMAPIVersion)

    [System.Uri]$URI = [System.Uri]::new( $URIString )
    [System.String]$AbsoluteURI = $URI.AbsoluteUri
    [System.String]$ContentType = 'application/json'
    
    switch ($EnrollmentState) {
        'Enable' {
            Write-Information -MessageData "Set to enable Windows Server Management by Azure Arc on Server: '$MachineName'."
            [System.Collections.Hashtable]$DataTable = @{
                location   = $MachineLocation;
                properties = @{
                    softwareAssurance = @{
                        softwareAssuranceCustomer = $true;
                    };
                };
            };
        }
        'Disable' {
            Write-Information -MessageData "Set to disable Windows Server Management by Azure Arc on Server: '$MachineName'."
            [System.Collections.Hashtable]$DataTable = @{
                location   = $MachineLocation;
                properties = @{
                    softwareAssurance = @{
                        softwareAssuranceCustomer = $false;
                    };
                };
            };
        }
    }

    Write-Information -MessageData "Building response table..."
    $JSON = $DataTable | ConvertTo-Json;
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
        coreCount        = $Machine.coreCount;
        logicalCoreCount = $Machine.logicalCoreCount;

    }
    try {
        $ErrorActionPreference = 'SilentlyContinue'
        if ($PSCmdlet.ShouldProcess($MachineName)) {
            Write-Information -MessageData "Creating call to Azure REST API."
            $Response = Invoke-RestMethod -Method 'PUT' -Uri $AbsoluteURI -ContentType $ContentType -Headers $BearerTokenHeaderTable -Body $JSON
            $ResponseTable.Add('ProvisioningState', $Response.Properties.provisioningState)
            $ResponseTable.Add('SoftwareAssurance', $Response.Properties.softwareAssurance)
            $ResponseTable.Add('Result', 'Success')
            $ResponseTable.Add('ErrorMessage', '')
            Write-Information -MessageData "Machine: '$MachineName'. Result: 'Success'."
        }
        else {
            # Putting in a call to Write-Information because Invoke-RestMethod doesn't support 'WhatIf'.
            # This may be short lived once changed to Invoke-AzRestMethod, which does.
            [System.String]$JSONString = [System.Convert]::ToString($JSON)
            Write-Information -MessageData "Would run 'Invoke-RestMethod' with the following parameter values: URI - '$AbsoluteURI', ContentType - '$ContentType', Body - '$JSONString'."
            Write-Information -MessageData "Machine: '$MachineName'. Result: 'WhatIf'."
            $ResponseTable.Add('ProvisioningState', 'N/A - WhatIf')
            $ResponseTable.Add('SoftwareAssurance', 'N/A - WhatIf')
            $ResponseTable.Add('Result', 'N/A - WhatIf')
            $ResponseTable.Add('ErrorMessage', 'N/A - WhatIf')
        }
    }
    catch {
        Write-Warning -Message "Machine: '$MachineName'. Result: 'Error'. Continuing."
        $ResponseTable.Add('ProvisioningState', $Response.Properties.provisioningState)
        $ResponseTable.Add('SoftwareAssurance', $Response.Properties.softwareAssurance)
        $ResponseTable.Add('Result', 'Error')
        $ResponseTable.Add('ErrorMessage', ($_.Errordetails.Message | ConvertFrom-Json).Error.Message)
    }

    $ResponseTable
}

# Create an array list to collect responses for output at the end.
[System.Collections.ArrayList]$ResponseArray = @()
## Discovery
Write-Information -MessageData 'Getting Bearer token.'
[System.Collections.Hashtable]$BearerTokenHeaderTable = CreateBearerTokenHeaderTable

switch ($PSCmdlet.ParameterSetName) {
    '__AllParameterSets' {
        Write-Information -MessageData 'Will attempt to enroll all Arc-enabled Servers.'

        Write-Information -MessageData 'Discovering machines...'
        [System.Array]$MachinesArray = DiscoverMachines -EnrollmentState $EnrollmentState -TakeFirst $TakeFirst
    }
    'TenantIDs' {
        Write-Information -MessageData "Will attempt to enroll all Arc-enabled Servers across all Azure subscriptions in Entra ID tenant: '$TenantIDs'."

        Write-Information -MessageData 'Discovering machines...'
        [System.Array]$MachinesArray = DiscoverMachines -EnrollmentState $EnrollmentState -TenantIDs $TenantIDs -TakeFirst $TakeFirst
    }
    'ManagementGroupIDs' {
        if (1 -lt $ManagementGroupIDs.Count) {
            [System.String]$ManagementGroupIDsString = $ManagementGroupIDs -join ', '
        }
        else {
            [System.String]$ManagementGroupIDsString = $ManagementGroupIDs
        }
        Write-Information -MessageData "Will attempt to enroll all Arc-enabled Servers under Management Groups(s): '$ManagementGroupIDsString'."

        Write-Information -MessageData 'Discovering machines...'
        [System.Array]$MachinesArray = DiscoverMachines -EnrollmentState $EnrollmentState -ManagementGroupIDs $ManagementGroupIDs -TakeFirst $TakeFirst
    }
    'Subscriptions' {
        if (1 -lt $SubscriptionIDs.Count) {
            [System.String]$SubscriptionIDsString = $SubscriptionIDs -join ', '
        }
        else {
            [System.String]$SubscriptionIDsString = $SubscriptionIDs
        }
        Write-Information -MessageData "Will attempt to enroll all Arc-enabled Servers in Azure subscription(s): '$SubscriptionIDsString'."

        Write-Information -MessageData 'Discovering machines...'
        [System.Array]$MachinesArray = DiscoverMachines -EnrollmentState $EnrollmentState -SubscriptionIDs $SubscriptionIDs -TakeFirst $TakeFirst
    }
    'ResourceGroupOrMachines' {
        [System.String]$ThisAzSubscriptionName = $GetAzContext.Subscription.Name
        [System.String]$ThisAzSubscriptionID = $GetAzContext.Subscription.Id

        if ($PSBoundParameters.ContainsKey('ResourceGroupNames') -and (!($PSBoundParameters.ContainsKey('MachineNames')))) {
            Write-Information -MessageData "Will attempt to enroll all Arc-enabled Servers in subscription with name: '$ThisAzSubscriptionName', ID: '$ThisAzSubscriptionID', and resource group: '$ResourceGroupNames'."
            [System.Array]$MachinesArray = DiscoverMachines -EnrollmentState $EnrollmentState -ResourceGroupNames $ResourceGroupNames -TakeFirst $TakeFirst
        }
        elseif ((!($PSBoundParameters.ContainsKey('ResourceGroupNames'))) -and $PSBoundParameters.ContainsKey('MachineNames')) {
            if (1 -lt $MachineNames.Count) {
                [System.String]$MachineNamesString = $MachineNames -join ', '
            }
            else {
                [System.String]$MachineNamesString = $MachineNames
            }
            Write-Information -MessageData "Will attempt to enroll these specific Arc-enabled Servers across resource groups in the current Azure subscription: '$MachineNamesString'."
            [System.Array]$MachinesArray = DiscoverMachines -EnrollmentState $EnrollmentState -MachineNames $MachineNames -TakeFirst $TakeFirst
        }
        else {
            if (1 -lt $MachineNames.Count) {
                [System.String]$MachineNamesString = $MachineNames -join ', '
            }
            else {
                [System.String]$MachineNamesString = $MachineNames
            }

            Write-Information -MessageData "Will attempt to enroll these specific Arc-enabled Servers in subscription with name: '$ThisAzSubscriptionName', ID: '$ThisAzSubscriptionID', and resource group: '$ResourceGroupNames'.'
            Write-Information -MessageData 'Machine names: '$MachineNamesString'."
            [System.Array]$MachinesArray = DiscoverMachines -EnrollmentState $EnrollmentState -ResourceGroupNames $ResourceGroupNames -MachineNames $MachineNames -TakeFirst $TakeFirst
        }
    }
}

if ($PSBoundParameters.ContainsKey('ExcludeMachineResourceIDs')) {
    Write-Information -MessageData 'Validating Resource ID format.'
    $ExcludeMachineResourceIDs | ForEach-Object -Process {
        [System.Collections.ArrayList]$RIDArray = @()
        [System.Collections.ArrayList]$RIDArray = $_.Split('/')
        [System.Int32]$RIDElementCount = $RIDArray.Count
        [System.String]$Subscriptions = $RIDArray[1]
        [System.String]$SubscriptionID = $RIDArray[2]
        [System.String]$ResourceGroups = $RIDArray[3]
        [System.String]$Providers = $RIDArray[5]
        [System.String]$ResourceProvider = $RIDArray[6]
        [System.String]$Machines = $RIDArray[7]

        if (9 -ne $RIDElementCount) {
            Write-Error -Message "The supplied Resource ID: '$_' should have nine elements when split and does not."
            throw
        }

        if ('subscriptions' -ne $Subscriptions) {
            Write-Error -Message 'Subscription format validation failed.'
            throw
        }

        if (!([System.Guid]::TryParse($SubscriptionID, $([ref][System.Guid]::Empty)))) {
            Write-Error -Message 'Subscription ID format validation failed.'
            throw
        }

        if ('resourceGroups' -ne $ResourceGroups) {
            Write-Error -Message 'Resource Groups format validation failed.'
            throw
        }

        if ('providers' -ne $Providers) {
            Write-Error -Message 'Providers format validation failed.'
            throw
        }

        if ('Microsoft.HybridCompute' -ne $ResourceProvider) {
            Write-Error -Message "The supplied Resource Provider: '$ResourceProvider' should be 'Microsoft.HybridCompute'."
            throw
        }

        if ('machines' -ne $Machines) {
            Write-Error -Message 'Machines format validation failed.'
            throw
        }
    }

    Write-Information -MessageData 'Will exclude the following Resource IDs from enrolling:'
    $ExcludeMachineResourceIDs | ForEach-Object -Process {
        Write-Information -MessageData $_
    }

    $MachinesArray = $MachinesArray | Where-Object -FilterScript {
        $_.ResourceID -notin $ExcludeMachineResourceIDs
    }
}

[System.Int32]$MachinesArrayCount = $MachinesArray.Count
if (1 -le $MachinesArrayCount) {
    Write-Information -MessageData "Found: '$MachinesArrayCount' eligible Arc-enabled Servers."

    Write-Information -MessageData 'About to start enrolling servers in benefits...'
    [System.Int32]$j = 1
    foreach ($Machine in $MachinesArray) {
        [System.String]$MachineName = $Machine.Name

        Write-Information -MessageData "Working on server: '$MachineName'. Server: '$j' of: '$MachinesArrayCount' servers."

        if ($PSBoundParameters.ContainsKey('ReportOnly')) {
            $Response = SetEnrollmentState -EnrollmentState $EnrollmentState -ResourceManagerURL $AzureResourceManagerURL -Machine $Machine -BearerTokenHeaderTable $BearerTokenHeaderTable -WhatIf
        }
        else {
            $Response = SetEnrollmentState -EnrollmentState $EnrollmentState -ResourceManagerURL $AzureResourceManagerURL -Machine $Machine -BearerTokenHeaderTable $BearerTokenHeaderTable
        }

        $ResponseArray.Add($Response) | Out-Null

        $j++
    }
}
else {
    switch ($PSCmdlet.ParameterSetName) {
        'TenantIDs' {
            Write-Information -MessageData 'Did not find any eligible Arc-enabled servers in tenant: '$TenantIDs'.'
        }
        'ManagementGroupIDs' {
            Write-Information -MessageData "Did not find any eligible Arc-enabled servers under Management Groups: '$ManagementGroupIDsString'."
        }
        'Subscriptions' {
            Write-Information -MessageData "Did not find any eligible Arc-enabled servers in subscriptions: '$SubscriptionIDsString'."
        }
        default {
            Write-Information -MessageData 'Did not find any Arc-enabled servers.'
        }
    }
}

### BEGIN: REPORT ###
if (0 -lt $ResponseArray.Count) {
    Write-Information -MessageData 'Results: '
    $ResponseArray | Select-Object -Property 'MachineName', 'Result', 'SoftwareAssurance', 'ResourceID' | Sort-Object -Property 'ResourceID' | Format-Table -AutoSize
    ### Test Report Directory validity and normalize provided parameter value
    if ($PSBoundParameters.ContainsKey('ReportDirectoryPath')) {
        [System.String]$ReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', $Now, '.csv')
        [System.String]$ReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $ReportFileName)
        if ($PSCmdlet.ShouldProcess($ReportFilePath)) {
            Write-Information -MessageData "Exporting CSV report to: '$ReportFilePath'."
            $ResponseArray | Export-Csv -LiteralPath $ReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation

            [System.Int32]$LogicalCoreCount = 0
            $ResponseArray | ForEach-Object -Process {
                if ($_.Result -eq 'Success') {
                    [System.Int32]$LogicalCoreCount = $LogicalCoreCount + $_.LogicalCoreCount
                }

            }
            Write-Information -MessageData "Total Logical Core Count Activated: '$LogicalCoreCount'"
        }
        else {
            Write-Information -MessageData "Would export CSV report to: '$ReportFilePath'."
            $ResponseArray | Export-Csv -LiteralPath $ReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
        }
    }
}
else {
    Write-Information -MessageData 'No results to output.'
}
### END: REPORT ###
### END
Write-Information -MessageData 'Exiting.'