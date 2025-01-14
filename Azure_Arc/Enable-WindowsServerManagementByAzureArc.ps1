#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources
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
    [System.String]$TenantID = '00000000-0000-0000-0000-000000000000'
    Connect-AzAccount -TenantID $TenantID
    Enable-WindowsServerManagementByAzureArc.ps1 -TenantID $TenantID

    .EXAMPLE
    Connect-AzAccount
    Enable-WindowsServerManagementByAzureArc.ps1 -AzSubscriptionID '00000000-0000-0000-0000-000000000000'

    .EXAMPLE
    Connect-AzAccount
    Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
    Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupName 'Prod-RG-Arc-01'

    .EXAMPLE
    Connect-AzAccount
    Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
    Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupName 'Prod-RG-Arc-01' -MachineNames 'Server1'

    .EXAMPLE
    Connect-AzAccount
    Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
    Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupName 'Prod-RG-Arc-01' -MachineNames 'Server1', 'Server2'
#>
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
        ParameterSetName = 'AzSubscription'
    )]
    [System.String]$AzSubscriptionID,
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
    [OutputType([System.Collections.ArrayList])]
    param (
        [System.String]$TenantID,
        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'AzSubscription'
        )]
        [System.String]$AzSubscriptionID,
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

    Write-Information -MessageData 'Getting Azure Arc-enabled Servers.'
    [System.Collections.ArrayList]$MachinesArray = @()
    try {
        $ErrorActionPreference = 'Stop'

        switch ($PSCmdlet.ParameterSetName) {
            'AzSubscription' {
                Write-Information -MessageData "Getting all Arc-enabled Servers in subscription: '$AzSubscriptionName'."
                Get-AzResource -ResourceType 'Microsoft.HybridCompute/machines' | Sort-Object -Property Name | ForEach-Object -Process {
                    $MachinesArray.Add($_) | Out-Null
                }
            }
            'ResourceGroupOrMachines' {

                if ($PSBoundParameters.ContainsKey('ResourceGroupName') -and (!($PSBoundParameters.ContainsKey('MachineNames')))) {
                    Write-Information -MessageData "Getting all Arc-enabled Servers in resource group: '$ResourceGroupName' in subscription: '$AzSubscriptionName'."
                    Get-AzResource -ResourceType 'Microsoft.HybridCompute/machines' | Where-Object -FilterScript { $_.ResourceGroupName -eq $ResourceGroupName } | Sort-Object -Property Name | ForEach-Object -Process {
                        $MachinesArray.Add($_) | Out-Null
                    }
                }
                elseif ((!($PSBoundParameters.ContainsKey('ResourceGroupName'))) -and $PSBoundParameters.ContainsKey('MachineNames')) {
                    Write-Information -MessageData "Getting Arc-enabled Servers across resource groups in subscription: '$AzSubscriptionName'."
                    Get-AzResource -ResourceType 'Microsoft.HybridCompute/machines' | Where-Object -FilterScript { $_.Name -in $MachineNames } | Sort-Object -Property Name | ForEach-Object -Process {
                        $MachinesArray.Add($_) | Out-Null
                    }
                }
                else {
                    Write-Information -MessageData "Getting specific Arc-enabled Servers in resource group: '$ResourceGroupName' in subscription: '$AzSubscriptionName'."
                    Get-AzResource -ResourceType 'Microsoft.HybridCompute/machines' | Where-Object -FilterScript { ($_.ResourceGroupName -eq $ResourceGroupName) -and ($_.Name -in $MachineNames) } | Sort-Object -Property Name | ForEach-Object -Process {
                        $MachinesArray.Add($_) | Out-Null
                    }
                }
            }
        }

        Write-Information -MessageData 'Outputting result array.'
        $MachinesArray
    }
    catch {
        $_
        throw
    }
}

function AttestMachine {
    [CmdletBInding()]
    [OutputType([PSCustomObject])]
    param (
        [PSObject]$Machine,
        [System.Collections.Hashtable]$BearerTokenHeaderTable
    )
    [System.String]$ThisFunctionName = $MyInvocation.MyCommand
    Write-Information -MessageData "Running: '$ThisFunctionName'."

    [System.String]$MachineSubscriptionID = $Machine.SubscriptionID
    [System.String]$MachineName = $Machine.Name
    [System.String]$MachineResourceGroupName = $Machine.ResourceGroupName
    [System.String]$MachineLocation = $Machine.Location

    [System.String]$URIString = [System.String]::Concat('https://management.azure.com/subscriptions/', $MachineSubscriptionID, '/resourceGroups/', $MachineResourceGroupName, '/providers/Microsoft.HybridCompute/machines/', $MachineName, '/licenseProfiles/default?api-version=2023-10-03-preview')

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
        Write-Information -MessageData "Will attempt to attest to all Arc-enabled Servers across all Azure subscriptions in Entra ID tenant: '$TenantID'."
        [System.Collections.ArrayList]$AzSubscriptions = @()

        Write-Information -MessageData 'Getting subscriptions'

        ## TO-DO: 01.13.2025 - Add ability to filter out invalid offer types.
        Get-AzSubscription -TenantId $TenantID | Sort-Object -Property 'Name' | ForEach-Object -Process {
            $AzSubscriptions.Add($_) | Out-Null
        }

        [System.Int32]$i = 1
        [System.Int32]$AzSubscriptionCount = $AzSubscriptions.Count
        if (1 -le $AzSubscriptionCount) {
            Write-Information -MessageData "Found: '$AzSubscriptionCount' Azure subscriptions in tenant: '$TenantID'."

            Write-Information -MessageData 'Getting Bearer token.'
            [System.Collections.Hashtable]$BearerTokenHeaderTable = CreateBearerTokenHeaderTable

            foreach ($AzSubscription in $AzSubscriptions) {
                [System.String]$ThisAzSubscriptionName = $AzSubscription.Name
                [System.String]$ThisAzSubscriptionID = $AzSubscription.Id

                Write-Information -MessageData 'Setting context.'
                Get-AzSubscription -SubscriptionId $ThisAzSubscriptionID | Set-AzContext | Out-Null

                Write-Information -MessageData "Working on Arc-enabled Servers in subscription with name: '$ThisAzSubscriptionName' and ID: '$ThisAzSubscriptionID'. Subscription: '$i' of: '$AzSubscriptionCount' subscriptions."
                [System.Collections.ArrayList]$MachinesArray = @()
                DiscoverMachines -AzSubscriptionID $ThisAzSubscriptionID | ForEach-Object -Process {
                    $MachinesArray.Add($_) | Out-Null
                }

                [System.Int32]$MachinesArrayCount = $MachinesArray.Count
                if (1 -le $MachinesArrayCount) {
                    Write-Information -MessageData "Found: '$MachinesArrayCount' Arc-enabled Servers."

                    Write-Information -MessageData 'Looping through machines...'
                    [System.Int32]$j = 1
                    foreach ($Machine in $MachinesArray) {
                        [System.String]$MachineName = $Machine.Name

                        Write-Information -MessageData "Working on server: '$MachineName'. Server: '$j' of: '$MachinesArrayCount' servers."
                        $Response = AttestMachine -Machine $Machine -BearerTokenHeaderTable $BearerTokenHeaderTable

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
    'AzSubscription' {
        Write-Information -MessageData "Will attempt to attest to all Arc-enabled Servers in Azure subscription: '$AzSubscriptionID'."

        if ($AzSubscriptionID -ne $GetAzContext.Subscription.Id) {
            Write-Information -MessageData 'Setting context.'
            Get-AzSubscription -SubscriptionId $AzSubscriptionID | Set-AzContext | Out-Null

            Write-Information -MessageData 'Getting Azure Context again.'
            $GetAzContext = Get-AzContext
        }

        Write-Information -MessageData 'Getting Bearer token.'
        [System.Collections.Hashtable]$BearerTokenHeaderTable = CreateBearerTokenHeaderTable

        [System.String]$ThisAzSubscriptionName = $GetAzContext.Subscription.Name
        [System.String]$ThisAzSubscriptionID = $AzSubscriptionID

        Write-Information -MessageData "Working on Arc-enabled Servers in subscription with name: '$ThisAzSubscriptionName' and ID: '$ThisAzSubscriptionID'."
        [System.Collections.ArrayList]$MachinesArray = @()
        DiscoverMachines -AzSubscriptionID $ThisAzSubscriptionID | ForEach-Object -Process {
            $MachinesArray.Add($_) | Out-Null
        }
    }
    'ResourceGroupOrMachines' {
        [System.String]$ThisAzSubscriptionName = $GetAzContext.Subscription.Name
        [System.String]$ThisAzSubscriptionID = $GetAzContext.Subscription.Id

        Write-Information -MessageData 'Getting Bearer token.'
        [System.Collections.Hashtable]$BearerTokenHeaderTable = CreateBearerTokenHeaderTable

        if ($PSBoundParameters.ContainsKey('ResourceGroupName') -and (!($PSBoundParameters.ContainsKey('MachineNames')))) {
            Write-Information -MessageData "Will attempt to attest to all Arc-enabled Servers in subscription with name: '$ThisAzSubscriptionName', ID: '$ThisAzSubscriptionID', and resource group: '$ResourceGroupName'."
            [System.Collections.ArrayList]$MachinesArray = @()
            DiscoverMachines -ResourceGroupName $ResourceGroupName | ForEach-Object -Process {
                $MachinesArray.Add($_) | Out-Null
            }
        }
        elseif ((!($PSBoundParameters.ContainsKey('ResourceGroupName'))) -and $PSBoundParameters.ContainsKey('MachineNames')) {
            if (1 -lt $MachineNames.Count) {
                [System.String]$MachineNameString = $MachineNames -join ', '
            }
            else {
                [System.String]$MachineNameString = $MachineNames
            }
            Write-Information -MessageData "Will attempt to attest to these specific Arc-enabled Servers across resource groups in the current Azure subscription: '$MachineNameString'."
            [System.Collections.ArrayList]$MachinesArray = @()
            DiscoverMachines -MachineNames $MachineNames | ForEach-Object -Process {
                $MachinesArray.Add($_) | Out-Null
            }
        }
        else {
            if (1 -lt $MachineNames.Count) {
                [System.String]$MachineNameString = $MachineNames -join ', '
            }
            else {
                [System.String]$MachineNameString = $MachineNames
            }

            Write-Information -MessageData "Will attempt to attest to these specific Arc-enabled Servers in subscription with name: '$ThisAzSubscriptionName', ID: '$ThisAzSubscriptionID', and resource group: '$ResourceGroupName'."
            Write-Information -MessageData "Machine names: '$MachineNameString'."
            [System.Collections.ArrayList]$MachinesArray = @()
            DiscoverMachines -ResourceGroupName $ResourceGroupName -MachineNames $MachineNames | ForEach-Object -Process {
                $MachinesArray.Add($_) | Out-Null
            }
        }
    }
    default {
        Write-Warning -Message 'Please supply at least one parameter and try again.'
        throw
    }
}

# Separate switch block for attesting when working in a single subscription, resource group, or with individual machine names
# The attestation code is identical once working at these scopes.

switch ($PSCmdlet.ParameterSetName) {
    { $_ -in @('AzSubscription', 'ResourceGroupOrMachines') } {
        [System.Int32]$MachinesArrayCount = $MachinesArray.Count
        if (1 -le $MachinesArrayCount) {
            Write-Information -MessageData "Found: '$MachinesArrayCount' Arc-enabled Servers."

            Write-Information -MessageData 'Looping through machines...'
            [System.Int32]$j = 1
            foreach ($Machine in $MachinesArray) {
                [System.String]$MachineName = $Machine.Name

                Write-Information -MessageData "Working on server: '$MachineName'. Server: '$j' of: '$MachinesArrayCount' servers."
                $Response = AttestMachine -Machine $Machine -BearerTokenHeaderTable $BearerTokenHeaderTable

                $ResponseArray.Add($Response) | Out-Null

                $j++
            }

            Write-Information -MessageData 'Results: '
            $ResponseArray | Select-Object -Property 'MachineName', 'ProvisioningState', 'ResourceID', 'SoftwareAssurance' | Sort-Object -Property 'ResourceID' | Format-Table -AutoSize
        }
        else {
            Write-Information -MessageData 'Did not find any Arc-enabled servers.'
        }
    }
}

Write-Information -MessageData 'Exiting.'