[CmdletBInding()]
param(
    [Parameter(
        Mandatory = $true
    )]
    [System.String]$AzSubscriptionID,
    [Parameter(
        Mandatory = $true
    )]
    [System.String]$ResourceGroupName,
    [Parameter(
        Mandatory = $false
    )]
    [System.String[]]$MachineNames
)
$InformationPreference = 'Continue'
$GetAzContext = Get-AzContext

if ($GetAzContext) {
    Write-Information -MessageData 'Connected to Azure.'
}
else {
    Write-Error -Message 'Not connected to Azure. Please connect first and try again.'
    throw
}

if ($AzSubscriptionID -ne $GetAzContext.Subscription.Id) {
    Write-Information -MessageData "Changing context to subscription: '$AzSubscriptionID'."
    Get-AzSubscription -SubscriptionId $AzSubscriptionID | Set-AzContext

    Write-Information -MessageData 'Getting Azure Context again.'
    $GetAzContext = Get-AzContext
}

Write-Information -MessageData 'Getting Azure Arc-enabled Servers.'
[System.Collections.ArrayList]$MachinesArray = @()
try {
    $ErrorActionPreference = 'Stop'

    if ($PSBoundParameters.ContainsKey('MachineNames')) {
        Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.HybridCompute/machines' | Where-Object -FilterScript { $_.Name -in $MachineNames } | Sort-Object -Property Name | ForEach-Object -Process {
            $MachinesArray.Add($_) | Out-Null
        }
    }
    else {
        Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.HybridCompute/machines' | Sort-Object -Property Name | ForEach-Object -Process {
            $MachinesArray.Add($_) | Out-Null
        }
    }
}
catch {
    $_
    throw
}

[System.Int32]$i = 1
[System.Int32]$MachinesArrayCount = $MachinesArray.Count
if (0 -lt $MachinesArray.Count) {
    Write-Information -MessageData "Found: '$MachinesArrayCount' Arc-enabled Servers."

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
    }
    catch {
        $_
        throw
    }

    Write-Information -MessageData 'Looping through machines...'
    [System.Collections.ArrayList]$ResponseArray = @()
    foreach ($Machine in $MachinesArray) {
        [System.String]$MachineName = $Machine.Name
        [System.String]$MachineResourceGroupName = $Machine.ResourceGroupName
        [System.String]$MachineLocation = $Machine.Location

        Write-Information -MessageData "Working on Arc-enabled Server: '$MachineName'. Server: '$i' of: '$MachinesArrayCount' servers."
        [System.String]$URIString = [System.String]::Concat('https://management.azure.com/subscriptions/', $AzSubscriptionID, '/resourceGroups/', $MachineResourceGroupName, '/providers/Microsoft.HybridCompute/machines/', $MachineName, '/licenseProfiles/default?api-version=2023-10-03-preview')

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

            $Response = Invoke-RestMethod -Method 'PUT' -Uri $AbsoluteURI -ContentType $ContentType -Headers $HeaderTable -Body $JSON
            [PSCustomObject]$ResponseTable = @{
                MachineName       = $MachineName
                ProvisioningState = $Response.Properties.provisioningState
                SoftwareAssurance = $Response.Properties.softwareAssurance
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
$ResponseArray | Select-Object -Property 'MachineName', 'ProvisioningState', 'SoftwareAssurance' | Format-Table -AutoSize

Write-Information -MessageData 'Exiting.'