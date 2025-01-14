[CmdletBInding()]
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
        ParameterSetName = 'ResourceGroup'
    )]
    [System.String]$ResourceGroupName,
    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'Machines'
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

function DiscoverMachines {
    [PsCmdletbinding()]
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
            ParameterSetName = 'ResourceGroup'
        )]
        [System.String]$ResourceGroupName,
        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'Machines'
        )]
        [System.String[]]$MachineNames
    )
    [System.String]$ThisFunctionName = $MyInvocation.MyCommand
    Write-Information -MessageData "Running: '$ThisFunctionName'."

    Write-Information -MessageData 'Getting subscription...'
    $GetAzSubscription = Get-AzSubscription -SubscriptionId $AzSubscriptionID
    [System.String]$AzSubscriptionName = $GetAzSubscription.Name

    Write-Information -MessageData 'Getting Azure Arc-enabled Servers.'
    [System.Collections.ArrayList]$MachinesArray = @()
    try {
        $ErrorActionPreference = 'Stop'

        if ($PSBoundParameters.ContainsKey('MachineNames')) {
            Write-Information -MessageData "Getting specific Arc-enabled Servers in resource group: '$ResourceGroupName' in subscription: '$AzSubscriptionName'."
            Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.HybridCompute/machines' | Where-Object -FilterScript { $_.Name -in $MachineNames } | Sort-Object -Property Name | ForEach-Object -Process {
                $MachinesArray.Add($_) | Out-Null
            }
        }
        elseif ($PSBoundParameters.ContainsKey('ResourceGroupName')) {
            Write-Information -MessageData "Getting all Arc-enabled Servers in resource group: '$ResourceGroupName' in subscription: '$AzSubscriptionName'."
            Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.HybridCompute/machines' | Sort-Object -Property Name | ForEach-Object -Process {
                $MachinesArray.Add($_) | Out-Null
            }
        }
        else {
            Write-Information -MessageData "Getting all Arc-enabled Servers in subscription: '$AzSubscriptionName'."
            Get-AzResource -ResourceType 'Microsoft.HybridCompute/machines' | Sort-Object -Property Name | ForEach-Object -Process {
                $MachinesArray.Add($_) | Out-Null
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

function CreateBearerTokenHeaderTable {
    [PsCmdletbinding()]
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

function AttestMachine {
    [PsCmdletbinding()]
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
            ServerNumber      = $i;
            MachineName       = $MachineName;
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

switch ($PSCmdlet.ParameterSetName) {
    'AzEnvironment' {
        Write-Information -MessageData "Will attempt to attest to every Arc-enabled Server across all Azure subscriptions in Entra ID tenant: '$TenantID'."
        [System.Collections.ArrayList]$AzSubscriptions = @()

        Write-Information -MessageData 'Getting subscriptions'

        ## TO-DO: 01.13.2025 - Add ability to filter out invalid offer types.
        Get-AzSubscription -TenantId $TenantID | ForEach-Object -Process {
            $AzSubscriptions.Add($_) | Out-Null
        }

        [System.Int32]$i = 1
        [System.Int32]$AzSubscriptionCount = $AzSubscriptions.Count
        if (1 -le $AzSubscriptionCount) {
            Write-Information -MessageData "Found: '$AzSubscriptionCount' Azure subscriptions in tenant: '$TenantID'."

            [System.Collections.Hashtable]$BearerTokenHeaderTable = CreateBearerTokenHeaderTable

            foreach ($AzSubscription in $AzSubscriptions) {
                [System.String]$ThisAzSubscriptionName = $AzSubscription.Name
                [System.String]$ThisAzSubscriptionID = $AzSubscription.Id

                Write-Information -MessageData "Working on Arc-enabled Servers in subscription with name: '$ThisAzSubscriptionName' and id: '$ThisAzSubscriptionID'. Subscription: '$i' of: '$AzSubscriptionCount' subscriptions."
                Write-Information -MessageData 'Setting context.'
                Get-AzSubscription -SubscriptionId $ThisAzSubscriptionID | Set-AzContext
                [System.Collections.ArrayList]$MachinesArray = DiscoverMachines -AzSubscriptionID $ThisAzSubscriptionID

                [System.Int32]$j = 1
                [System.Int32]$MachinesArrayCount = $MachinesArray.Count
                if (1 -le $MachinesArrayCount) {
                    Write-Information -MessageData "Found: '$MachinesArrayCount' Arc-enabled Servers."

                    Write-Information -MessageData 'Looping through machines...'
                    [System.Collections.ArrayList]$ResponseArray = @()
                    foreach ($Machine in $Machines) {

                        $Response = AttestMachine -Machine $Machine -BearerTokenHeaderTable $BearerTokenHeaderTable

                        $ResponseArray.Add($Response) | Out-Null

                        $j++
                    }
                }
                else {
                    Write-Information -MessageData 'Found no Arc-enabled servers in current subscription.'
                }

                $i++
            }
        }
        else {
            Write-Warning -Message "Found no eligible Azure subscriptions attached to tenant: '$TenantID'."
        }
    }
    'AzSubscription' {
        Write-Information -MessageData "Will attempt to attest to every Arc-enabled Server in Azure subscription: '$AzSubscriptionID'."
    }
    'ResourceGroup' {
        Write-Information -MessageData "Will attempt to attest to every Arc-enabled Server in Azure resource group: '$ResourceGroupName'."
    }
    'Machines' {
        if ($MachineNames.Count -gt 1) {
            [System.String]$MachineNameString = $MachineNames -join ', '
        }
        else {
            [System.String]$MachineNameString = $MachineNames
        }
        Write-Information -MessageData "Will attempt to attest to these specific Arc-enabled Servers in the current Azure subscription: '$MachineNameString'."
    }
}

if ($PSBoundParameters.ContainsKey('AzSubscriptionID') -and ($AzSubscriptionID -ne $GetAzContext.Subscription.Id)) {
    Write-Information -MessageData "Changing context to subscription: '$AzSubscriptionID'."
    Get-AzSubscription -SubscriptionId $AzSubscriptionID | Set-AzContext | Out-Null

    Write-Information -MessageData 'Getting Azure Context again.'
    $GetAzContext = Get-AzContext
}

[System.Int32]$i = 1
[System.Int32]$MachinesArrayCount = $MachinesArray.Count

if (0 -lt $MachinesArray.Count) {
    Write-Information -MessageData "Found: '$MachinesArrayCount' Arc-enabled Servers."



    foreach ($Machine in $MachinesArray) {
        [System.String]$MachineName = $Machine.Name
        Write-Information -MessageData "Enabling Windows Server Management by Azure Arc on Server: '$MachineName'.  Server: '$i' of: '$MachinesArrayCount' servers."

        try {
            $ErrorActionPreference = 'Stop'

            [System.Collections.Hashtable]$HeaderTable = CreateBearerTokenHeaderTable

            $Response = AttestMachine -Machine $Machine
            [PSCustomObject]$ResponseTable = @{
                ServerNumber      = $i;
                MachineName       = $MachineName;
                ProvisioningState = $Response.Properties.provisioningState;
                SoftwareAssurance = $Response.Properties.softwareAssurance;
            }
            $ResponseArray.Add($ResponseTable) | Out-Null

        }
        catch {
            $_
            throw
        }

        $i++
    }
}
else {
    Write-Warning -Message "Didn't find any Arc-enabled Servers :( ."
}
Write-Information -MessageData 'Results: '
$ResponseArray | Select-Object -Property 'ServerNumber', 'MachineName', 'ProvisioningState', 'SoftwareAssurance' | Format-Table -AutoSize

Write-Information -MessageData 'Exiting.'