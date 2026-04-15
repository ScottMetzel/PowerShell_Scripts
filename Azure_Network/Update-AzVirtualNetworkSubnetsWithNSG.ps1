$InformationPreference = 'Continue'
[System.String]$subscriptionId = '<Insert-Subscription-ID-Here>'
[System.String]$ResourceGroupName = 'Test-RG-Network-01'
[System.String]$VirtualNetworkName = 'Test-VNET-Spoke-01'
[System.String]$NSGName = 'Test-NSG-Spoke-01'

if ((Get-AzContext).Subscription.Id -ne $subscriptionId) {
    Write-Information -MessageData "Switching to subscription ID: $subscriptionId"
    Select-AzSubscription -SubscriptionId $subscriptionId
}

# Define parameters for the Network Security Group
$NSGParams = @{
    ResourceGroupName = $ResourceGroupName
    Name              = $NSGName
}

Write-Information -MessageData "Retrieving Network Security Group: $($NSGParams.Name) in Resource Group: $($NSGParams.ResourceGroupName)"
try {
    $ErrorActionPreference = 'Stop'
    $GetAzNetworkSecurityGroup = Get-AzNetworkSecurityGroup @NSGParams
}
catch {
    Write-Error "Error getting NSG: $_"
}
# Define parameters for the virtual network and subnet configuration

$VNetParams = @{
    ResourceGroupName = $ResourceGroupName
    Name              = $VirtualNetworkName
}

# Retrieve the virtual network
Write-Information -MessageData "Retrieving Virtual Network: $($VNetParams.Name) in Resource Group: $($VNetParams.ResourceGroupName)"
try {
    $ErrorActionPreference = 'Stop'
    $GetAzVirtualNetwork = Get-AzVirtualNetwork @VNetParams

}
catch {
    Write-Error "Error getting Virtual Network: $_"
}

# Retrieve all subnets in the virtual network
Write-Information -MessageData "Retrieving Subnets in Virtual Network: $($GetAzVirtualNetwork.Name)"
$GetSubnets = $GetAzVirtualNetwork.Subnets

[System.Int32]$TotalSubnets = $GetSubnets.Count
Write-Information -MessageData "Found: '$TotalSubnets' in Virtual Network: $($GetAzVirtualNetwork.Name)"
[System.Int32]$i = 1

# Foreach subnet, udpate the subnet configuration to associate the NSG
foreach ($Subnet in $GetSubnets) {
    Write-Information -MessageData "Updating Subnet: $($Subnet.Name) with NSG: $($GetAzNetworkSecurityGroup.Name). Processing subnet '$i' of '$TotalSubnets'."
    # Update the subnet configuration
    $SubnetParams = @{
        VirtualNetwork                 = $GetAzVirtualNetwork
        NetworkSecurityGroupId         = $GetAzNetworkSecurityGroup.Id
        Name                           = $Subnet.Name
        AddressPrefix                  = $Subnet.AddressPrefix
        Delegation                     = $Subnet.Delegations
        #ServiceEndpoint                = $Subnet.ServiceEndpoints
        PrivateEndpointNetworkPolicies = 'Enabled'
    }
    Set-AzVirtualNetworkSubnetConfig @SubnetParams

    $i++
}

# Update the virtual network
Write-Information -MessageData "Updating Virtual Network: $($GetAzVirtualNetwork.Name) with modified subnet configurations."
Set-AzVirtualNetwork -VirtualNetwork $GetAzVirtualNetwork