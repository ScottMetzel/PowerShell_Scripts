<#
    .SYNOPSIS
    This script attempts to enroll Arc-enabled Servers in Windows Server Management.

    .DESCRIPTION
    This script attempts to enroll Arc-enabled Servers in Windows Server Management.

    More information about Windows Server Management Enabled by Azure Arc can be found here:
    https://learn.microsoft.com/en-us/azure/azure-arc/servers/windows-server-management-overview

    This script makes state changes at the Azure management plane. It does not make changes within an OS.

    It requires the Az.Accounts, Az.Resources, and PowerShell Utility modules.

    This script is provided AS-IS with no warranties or claims it'll work as described. Please review the code and test in a safe environment.
    Executing this script is done at your own risk ;) .

    .NOTES
    ===========================================================================
    Created with: 	Microsoft Visual Studio Code
    Created on:   	01/08/2025 6:17 PM
    Created by:   	Scott Metzel
    Organization: 	-
    Filename:     	Enable-WindowsServerManagementByAzureArc.ps1
    Comments:     	This script builds on Kevin Sullivan's original script, here:
                    https://github.com/kevinsul/arc-ws-sa-enable/blob/main/arc-ws-sa-enable.ps1
    ===========================================================================

    .PARAMETER TenantID
    Supply the ID of an Entra ID tenant. Sets the script to run at an Azure environment scope across all subscriptions attached to the tenant.

    .PARAMETER AzSubscriptionID
    Supply an Azure subscription ID. Sets the script to run at an Azure subscription scope.

    .PARAMETER ResourceGroupName
    Supply the name of a resource group in the current Azure contxt. Sets the script to run at an Azure resource group scope.

    .PARAMETER MachineNames
    Supply a string array of machine names. Sets the script to run at a subscription scope, but across resource groups within the subscription.

    .EXAMPLE
    PS> [System.String]$TenantID = '00000000-0000-0000-0000-000000000000'
    PS> Connect-AzAccount -TenantID $TenantID
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -TenantID $TenantID

    .EXAMPLE
    PS> Connect-AzAccount
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -AzSubscriptionIDs '00000000-0000-0000-0000-000000000000'

    .EXAMPLE
    PS> Connect-AzAccount
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -AzSubscriptionIDs '00000000-0000-0000-0000-000000000000', '12345678-9012-3456-7890-123456789012'

    .EXAMPLE
    PS> Connect-AzAccount
    PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupName 'Prod-RG-Arc-01'

    .EXAMPLE
    PS> Connect-AzAccount
    PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupName 'Prod-RG-Arc-01' -MachineNames 'Server1'

    .EXAMPLE
    PS> Connect-AzAccount
    PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupName 'Prod-RG-Arc-01' -MachineNames 'Server1', 'Server2'

    .EXAMPLE
    PS> Connect-AzAccount
    PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
    PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -MachineNames 'Server1', 'Server2'

    .OUTPUTS
    System.Collections.ArrayList
#>
#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources
[CmdletBInding()]
[OutputType([System.Collections.ArrayList])]
param(
    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'AzEnvironment'
    )]
    [System.String]$TenantID,
    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'AzSubscriptions'
    )]
    [ValidateScript(
        {
            [guid]::TryParse($_, $([ref][guid]::Empty))
        }
    )]
    [System.String[]]$AzSubscriptionIDs,
    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'ResourceGroupOrMachines'
    )]
    [System.String]$ResourceGroupName,
    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'ResourceGroupOrMachines'
    )]
    [System.String[]]$MachineNames
)
$InformationPreference = 'Continue'

Write-Information -MessageData 'Getting current Azure context...'
$GetAzContext = Get-AzContext

if ($GetAzContext) {
    Write-Information -MessageData 'Connected to Azure.'
}
else {
    Write-Error -Message 'Not connected to Azure. Please connect first and try again.'
    throw
}

function CreateBearerTokenHeaderTable {
    [CmdletBInding()]
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
    [CmdletBInding()]
    [OutputType([System.Array])]
    param (
        [System.String]$TenantID,
        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'AzSubscriptions'
        )]
        [System.String]$AzSubscriptionIDs,
        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'ResourceGroupOrMachines'
        )]
        [System.String]$ResourceGroupName,
        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'ResourceGroupOrMachines'
        )]
        [System.String[]]$MachineNames
    )
    [System.String]$ThisFunctionName = $MyInvocation.MyCommand
    Write-Information -MessageData "Running: '$ThisFunctionName'."

    Write-Information -MessageData 'Getting context.'
    $GetAzContext = Get-AzContext
    [System.String]$AzSubscriptionName = $GetAzContext.Subscription.Name
    [System.Collections.ArrayList]$MachinesArray = @()

    try {
        $ErrorActionPreference = 'Stop'

        switch ($PSCmdlet.ParameterSetName) {
            'AzSubscriptions' {
                Write-Information -MessageData "Getting all Arc-enabled Windows Servers not already enrolled in subscription: '$AzSubscriptionName'."
                [System.String]$ResourceGraphQuery = "resources | where type =~ 'microsoft.hybridcompute/machines' and properties.osType=='windows' and properties.status=='Connected' and properties.licenseProfile.softwareAssurance.softwareAssuranceCustomer == true"

                Search-AzGraph -Query $ResourceGraphQuery | Sort-Object -Property Name | ForEach-Object -Process {
                    $MachinesArray.Add($_) | Out-Null
                }
            }
            'ResourceGroupOrMachines' {
                if ($PSBoundParameters.ContainsKey('ResourceGroupName') -and (!($PSBoundParameters.ContainsKey('MachineNames')))) {
                    Write-Information -MessageData "Getting all Arc-enabled Windows Servers not already enrolled in subscription: '$AzSubscriptionName' in resource group: '$ResourceGroupName' ."
                    [System.String]$ResourceGraphQuery = [System.String]::Concat("resources | where type =~ 'microsoft.hybridcompute/machines' and properties.osType=='windows' and properties.status=='Connected' and resourceGroup == '", $resourceGroupName, "' and properties.licenseProfile.softwareAssurance.softwareAssuranceCustomer != true")

                    Search-AzGraph -Query $ResourceGraphQuery | Sort-Object -Property Name | ForEach-Object -Process {
                        $MachinesArray.Add($_) | Out-Null
                    }
                }
                elseif ((!($PSBoundParameters.ContainsKey('ResourceGroupName'))) -and $PSBoundParameters.ContainsKey('MachineNames')) {
                    Write-Information -MessageData "Getting Arc-enabled Windows Servers not already enrolled across resource groups in subscription: '$AzSubscriptionName'."
                    if (1 -lt $MachineNames.Count) {
                        [System.String]$MachineNamesString = ($MachineNames | ForEach-Object { "'$_'" }) -join ','
                    }
                    else {
                        [System.String]$MachineNamesString = [System.String]::Concat('''', $MachineNames, '''')
                    }
                    [System.String]$MachineNameQueryArrayString = [System.String]::Concat('(', $MachineNamesString , ')')
                    [System.String]$ResourceGraphQuery = [System.String]::Concat("resources | where type =~ 'microsoft.hybridcompute/machines' and properties.osType=='windows' and properties.status=='Connected' and name in ", $MachineNameQueryArrayString, ' and properties.licenseProfile.softwareAssurance.softwareAssuranceCustomer != true')
                    Search-AzGraph -Query $ResourceGraphQuery | Sort-Object -Property Name | ForEach-Object -Process {
                        $MachinesArray.Add($_) | Out-Null
                    }
                }
                else {
                    Write-Information -MessageData "Getting specific Arc-enabled Windows Servers not already enrolled in resource group: '$ResourceGroupName' in subscription: '$AzSubscriptionName'."
                    if (1 -lt $MachineNames.Count) {
                        [System.String]$MachineNamesString = ($MachineNames | ForEach-Object { "'$_'" }) -join ','
                    }
                    else {
                        [System.String]$MachineNamesString = [System.String]::Concat('''', $MachineNames, '''')
                    }
                    [System.String]$MachineNameQueryArrayString = [System.String]::Concat('(', $MachineNamesString , ')')
                    [System.String]$ResourceGraphQuery = [System.String]::Concat("resources | where type =~ 'microsoft.hybridcompute/machines' and properties.osType=='windows' and properties.status=='Connected' and resourceGroup == '", $resourceGroupName, "' and name in ", $MachineNameQueryArrayString, ' and properties.licenseProfile.softwareAssurance.softwareAssuranceCustomer != true')
                    Search-AzGraph -Query $ResourceGraphQuery | Sort-Object -Property Name | ForEach-Object -Process {
                        $MachinesArray.Add($_) | Out-Null
                    }
                }
            }
        }

        Write-Information -MessageData 'Outputting array result.'
        $MachinesArray
    }
    catch {
        $_
        throw
    }
}

function EnrollMachine {
    [CmdletBInding()]
    [OutputType([PSCustomObject])]
    param (
        [PSObject]$Machine,
        [System.Collections.Hashtable]$BearerTokenHeaderTable,
        [ValidatePattern(
            '^(\d{4})(-)(\d{2})(-)(\d{2})($|(-preview)$)'
        )]
        [System.String]$ARMAPIVersion = '2024-07-10'
    )
    [System.String]$ThisFunctionName = $MyInvocation.MyCommand
    Write-Information -MessageData "Running: '$ThisFunctionName'."
    [System.Array]$ResourceIDArray = $Machine.ResourceId -split '/'
    [System.String]$MachineSubscriptionID = $Machine.subscriptionID
    [System.String]$MachineName = $Machine.Name
    [System.String]$MachineResourceGroupName = $ResourceIDArray[4]
    [System.String]$MachineLocation = $Machine.Location
    [System.String]$URIString = [System.String]::Concat('https://management.azure.com/subscriptions/', $MachineSubscriptionID, '/resourceGroups/', $MachineResourceGroupName, '/providers/Microsoft.HybridCompute/machines/', $MachineName, '/licenseProfiles/default?api-version=', $ARMAPIVersion)

    [System.Uri]$URI = [System.Uri]::new( $URIString )
    [System.String]$AbsoluteURI = $URI.AbsoluteUri
    [System.String]$ContentType = 'application/json'
    [System.Collections.Hashtable]$DataTable = @{
        location   = $MachineLocation;
        properties = @{
            softwareAssurance = @{
                softwareAssuranceCustomer = $true;
            };
        };
    };

    $JSON = $DataTable | ConvertTo-Json;
    Write-Information -MessageData "Enabling Windows Server Management by Azure Arc on Server: '$MachineName'."
    try {
        $ErrorActionPreference = 'Stop'

        $Response = Invoke-RestMethod -Method 'PUT' -Uri $AbsoluteURI -ContentType $ContentType -Headers $BearerTokenHeaderTable -Body $JSON
        [PSCustomObject]$ResponseTable = @{
            MachineName       = $MachineName;
            ResourceID        = $Machine.ResourceID
            ProvisioningState = $Response.Properties.provisioningState;
            SoftwareAssurance = $Response.Properties.softwareAssurance;
        }

        $ResponseTable
    }
    catch {
        $_
        throw
    }
}

# Create an array list to collect responses for output at the end.
[System.Collections.ArrayList]$ResponseArray = @()

switch ($PSCmdlet.ParameterSetName) {
    'AzEnvironment' {
        Write-Information -MessageData "Will attempt to enroll all Arc-enabled Servers across all Azure subscriptions in Entra ID tenant: '$TenantID'."

        Write-Information -MessageData 'Getting subscriptions'

        ## TO-DO: 01.13.2025 - Add ability to filter out invalid offer types.
        [System.Collections.ArrayList]$AzSubscriptionsArray = @()
        Get-AzSubscription -TenantId $TenantID | Sort-Object -Property 'Name' | ForEach-Object -Process {
            $AzSubscriptionsArray.Add($_) | Out-Null
        }

        [System.Int32]$i = 1
        [System.Int32]$AzSubscriptionArrayCount = $AzSubscriptionsArray.Count
        if (1 -le $AzSubscriptionArrayCount) {
            Write-Information -MessageData "Found: '$AzSubscriptionArrayCount' Azure subscriptions in tenant: '$TenantID'."

            Write-Information -MessageData 'Getting Bearer token.'
            [System.Collections.Hashtable]$BearerTokenHeaderTable = CreateBearerTokenHeaderTable

            foreach ($AzSubscription in $AzSubscriptionsArray) {
                [System.String]$ThisAzSubscriptionName = $AzSubscription.Name
                [System.String]$ThisAzSubscriptionID = $AzSubscription.Id

                Write-Information -MessageData 'Setting context.'
                Get-AzSubscription -SubscriptionId $ThisAzSubscriptionID | Set-AzContext | Out-Null

                Write-Information -MessageData "Working on Arc-enabled Servers in subscription with name: '$ThisAzSubscriptionName' and ID: '$ThisAzSubscriptionID'. Subscription: '$i' of: '$AzSubscriptionArrayCount' subscriptions."
                #[System.Collections.ArrayList]$MachinesArray = @()
                [System.Array]$MachinesArray = DiscoverMachines -AzSubscriptionIDs $ThisAzSubscriptionID

                [System.Int32]$MachinesArrayCount = $MachinesArray.Count
                if (1 -le $MachinesArrayCount) {
                    Write-Information -MessageData "Found: '$MachinesArrayCount' Arc-enabled Servers."

                    Write-Information -MessageData 'Looping through machines...'
                    [System.Int32]$j = 1
                    foreach ($Machine in $MachinesArray) {
                        [System.String]$MachineName = $Machine.Name

                        Write-Information -MessageData "Working on server: '$MachineName'. Server: '$j' of: '$MachinesArrayCount' servers."
                        $Response = EnrollMachine -Machine $Machine -BearerTokenHeaderTable $BearerTokenHeaderTable

                        $ResponseArray.Add($Response) | Out-Null

                        $j++
                    }
                }
                else {
                    Write-Information -MessageData 'Did not find any Arc-enabled servers in current subscription.'
                }

                $i++
            }
        }
        else {
            Write-Warning -Message "Found no eligible Azure subscriptions attached to tenant: '$TenantID'."
        }
    }
    'AzSubscriptions' {
        if (1 -lt $AzSubscriptionIDs.Count) {
            [System.String]$AzSubscriptionIDsString = $AzSubscriptionIDs -join ', '
        }
        else {
            [System.String]$AzSubscriptionIDsString = $AzSubscriptionIDs
        }
        Write-Information -MessageData "Will attempt to enroll all Arc-enabled Servers in Azure subscription(s): '$AzSubscriptionIDsString'."

        Write-Information -MessageData 'Getting Bearer token.'
        [System.Collections.Hashtable]$BearerTokenHeaderTable = CreateBearerTokenHeaderTable

        Write-Information -MessageData 'Getting Azure subscriptions.'
        [System.Collections.ArrayList]$AzSubscriptionsArray = @()

        $AzSubscriptionIDs | ForEach-Object -Process {
            $AzSubscription = Get-AzSubscription -SubscriptionId $_
            $AzSubscriptionsArray.Add($AzSubscription) | Out-Null
        }

        [System.Int32]$i = 1
        [System.Int32]$AzSubscriptionArrayCount = $AzSubscriptionsArray.Count
        foreach ($AzSubscription in $AzSubscriptionsArray) {
            [System.String]$ThisAzSubscriptionName = $AzSubscription.Name
            [System.String]$ThisAzSubscriptionID = $AzSubscription.Id

            Write-Information -MessageData 'Setting context.'
            Get-AzSubscription -SubscriptionId $ThisAzSubscriptionID | Set-AzContext | Out-Null

            Write-Information -MessageData "Working on Arc-enabled Servers in subscription with name: '$ThisAzSubscriptionName' and ID: '$ThisAzSubscriptionID'. Subscription: '$i' of: '$AzSubscriptionArrayCount' subscriptions."
            #[System.Collections.ArrayList]$MachinesArray = @()
            [System.Array]$MachinesArray = DiscoverMachines -AzSubscriptionIDs $ThisAzSubscriptionID

            [System.Int32]$MachinesArrayCount = $MachinesArray.Count
            if (1 -le $MachinesArrayCount) {
                Write-Information -MessageData "Found: '$MachinesArrayCount' Arc-enabled Servers."

                Write-Information -MessageData 'Looping through machines...'
                [System.Int32]$j = 1
                foreach ($Machine in $MachinesArray) {
                    [System.String]$MachineName = $Machine.Name

                    Write-Information -MessageData "Working on server: '$MachineName'. Server: '$j' of: '$MachinesArrayCount' servers."
                    $Response = EnrollMachine -Machine $Machine -BearerTokenHeaderTable $BearerTokenHeaderTable

                    $ResponseArray.Add($Response) | Out-Null

                    $j++
                }
            }
            else {
                Write-Information -MessageData 'Did not find any Arc-enabled servers in current subscription.'
            }

            $i++
        }
    }
    'ResourceGroupOrMachines' {
        [System.String]$ThisAzSubscriptionName = $GetAzContext.Subscription.Name
        [System.String]$ThisAzSubscriptionID = $GetAzContext.Subscription.Id

        Write-Information -MessageData 'Getting Bearer token.'
        [System.Collections.Hashtable]$BearerTokenHeaderTable = CreateBearerTokenHeaderTable

        if ($PSBoundParameters.ContainsKey('ResourceGroupName') -and (!($PSBoundParameters.ContainsKey('MachineNames')))) {
            Write-Information -MessageData "Will attempt to enroll all Arc-enabled Servers in subscription with name: '$ThisAzSubscriptionName', ID: '$ThisAzSubscriptionID', and resource group: '$ResourceGroupName'."
            #[System.Collections.ArrayList]$MachinesArray = @()
            [System.Array]$MachinesArray = DiscoverMachines -ResourceGroupName $ResourceGroupName
        }
        elseif ((!($PSBoundParameters.ContainsKey('ResourceGroupName'))) -and $PSBoundParameters.ContainsKey('MachineNames')) {
            if (1 -lt $MachineNames.Count) {
                [System.String]$MachineNamesString = $MachineNames -join ', '
            }
            else {
                [System.String]$MachineNamesString = $MachineNames
            }
            Write-Information -MessageData "Will attempt to enroll these specific Arc-enabled Servers across resource groups in the current Azure subscription: '$MachineNamesString'."
            #[System.Collections.ArrayList]$MachinesArray = @()
            [System.Array]$MachinesArray = DiscoverMachines -MachineNames $MachineNames
        }
        else {
            if (1 -lt $MachineNames.Count) {
                [System.String]$MachineNamesString = $MachineNames -join ', '
            }
            else {
                [System.String]$MachineNamesString = $MachineNames
            }

            Write-Information -MessageData "Will attempt to enroll these specific Arc-enabled Servers in subscription with name: '$ThisAzSubscriptionName', ID: '$ThisAzSubscriptionID', and resource group: '$ResourceGroupName'.'
            Write-Information -MessageData 'Machine names: '$MachineNamesString'."
            #[System.Collections.ArrayList]$MachinesArray = @()
            [System.Array]$MachinesArray = DiscoverMachines -ResourceGroupName $ResourceGroupName -MachineNames $MachineNames
        }
    }
    default {
        Write-Warning -Message 'Please supply at least one parameter and try again.'
        throw
    }
}

# Separate switch block for enrolling when working in a resource group or with individual machine names
# The enrollment code is identical once working at these scopes.

switch ($PSCmdlet.ParameterSetName) {
    { $_ -in @('ResourceGroupOrMachines') } {
        [System.Int32]$MachinesArrayCount = $MachinesArray.Count
        if (1 -le $MachinesArrayCount) {
            Write-Information -MessageData "Found: '$MachinesArrayCount' Arc-enabled Servers."

            Write-Information -MessageData 'Looping through machines...'
            [System.Int32]$j = 1
            foreach ($Machine in $MachinesArray) {
                [System.String]$MachineName = $Machine.Name

                Write-Information -MessageData "Working on server: '$MachineName'. Server: '$j' of: '$MachinesArrayCount' servers."
                $Response = EnrollMachine -Machine $Machine -BearerTokenHeaderTable $BearerTokenHeaderTable

                $ResponseArray.Add($Response) | Out-Null

                $j++
            }
        }
        else {
            Write-Information -MessageData 'Did not find any Arc-enabled servers.'
        }
    }
}

if (0 -lt $ResponseArray.Count) {
    Write-Information -MessageData 'Results: '
    $ResponseArray | Select-Object -Property 'MachineName', 'ProvisioningState', 'ResourceID', 'SoftwareAssurance' | Sort-Object -Property 'ResourceID' | Format-Table -AutoSize
}
else {
    Write-Information -MessageData 'No results to output.'
}

Write-Information -MessageData 'Exiting.'