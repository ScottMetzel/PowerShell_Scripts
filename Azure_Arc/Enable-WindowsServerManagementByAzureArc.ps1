[CmdletBInding()]
param(
    [System.String]$AzSubscriptionID,
    [System.String]$ResourceGroupName
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
}

Write-Information -MessageData 'Getting Azure Arc-enabled Servers.'
[System.Collections.ArrayList]$MachinesArray = @()
try {
    $ErrorActionPreference = 'Stop'
    Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.HybridCompute/machines' | ForEach-Object -Process {
        $MachinesArray.Add($_) | Out-Null
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
        $Token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
        [System.String]$BearerToken = [System.String]::Concat('Bearer ', $Token.AccessToken)
        [System.Collections.ArrayList]$Header = @{
            'Content-Type'  = 'application/json'
            'Authorization' = $BearerToken
        }
    }
    catch {
        $_
        throw
    }

    Write-Information -MessageData 'Looping through machines.'
    foreach ($Machine in $MachinesArray) {
        [System.String]$MachineName = $Machine.Name
        [System.String]$MachineResourceGroupName = $Machine.ResourceGroupName
        [System.String]$MachineLocation = $Machine.Location

        Write-Information -MessageData "Working on Arc-enabled Server: '$MachineName'. Server: '$i' of: '$MachinesArrayCount' servers."
        [System.String]$URIString = [System.String]::Concat('https://management.azure.com/subscriptions/', $AzSubscriptionID, '/resourceGroups/', $MachineResourceGroupName, '/providers/Microsoft.HybridCompute/machines/', $MachineName, '/licenseProfiles/default?api-version=2023-10-03-preview')

        [System.Uri]$URI = [System.Uri]::new( $URIString )
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
            [PSObject]$Response = Invoke-RestMethod -Method PUT -Uri $URI.AbsoluteUri -ContentType $ContentType -Headers $Header -Body $JSON;
            $Response.Properties
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

Write-Information -MessageData 'Exiting.'