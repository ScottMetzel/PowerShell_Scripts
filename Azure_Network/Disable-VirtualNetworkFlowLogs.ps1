[CmdletBinding()]
param()
# Ensures you do not inherit an AzContext in your runbook
# Write-Verbose -Message 'Disabling Azure context autosave.'
# Disable-AzContextAutosave -Scope Process

try {
    $ErrorActionPreference = 'Stop'

    # Connect to Azure with system-assigned managed identity
    [System.String]$VerboseMessage = [System.String]::Concat('Connecting to Azure using a System-Assigned Managed Identity. Context will be set to Azure Subscription ID: ''', $FirstAzSubscriptionID, '''.')
    Write-Verbose -Message $VerboseMessage
    Connect-AzAccount -Environment 'AzureCloud' -Identity -WarningAction SilentlyContinue
}
catch {
    Write-Error -Message $_
}

Write-Verbose -Message 'Getting Azure Subscriptions.'
[System.Collections.ArrayList]$AzSubscriptions = @()
Get-AzSubscription | Sort-Object -Property Name | ForEach-Object -Process {
    $AzSubscriptions.Add($_) | Out-Null
}

[System.Int32]$i = 1
[System.Int32]$AzSubscriptionCount = $AzSubscriptions.Count
Write-Verbose -Message 'Looping through Azure subscriptions to disable VNET Flow Logs...'
if (0 -lt $AzSubscriptionCount) {
    Write-Verbose -Message "Found: '$AzSubscriptionCount' Azure subscriptions."

    foreach ($AzSubscription in $AzSubscriptions) {
        [System.String]$AzSubscriptionName = $AzSubscription.Name
        [System.String]$AzSubscriptionID = $AzSubscription.Id
        Write-Verbose -Message "Setting context to subscription: '$AzSubscriptionName'. Subscription: '$i' of: '$AzSubscriptionCount' subscriptions."
        Get-AzSubscription -SubscriptionId $AzSubscriptionID | Set-AzContext | Out-Null

        [System.Collections.ArrayList]$AzFlowLogs = @()
        Write-Verbose -Message 'Getting Flow Logs with expanded properties. This may take a while...'
        Get-AzResource -ResourceType 'Microsoft.Network/networkWatchers/flowLogs' -ODataQuery "`$filter=SubscriptionId eq '$AzSubscriptionID'" -ExpandProperties | ForEach-Object -Process {
            $AzFLowLogs.Add($_) | Out-Null
        }

        [System.Int32]$AzFlowLogsCount = $AzFLowLogs.Count
        if (0 -lt $AzFlowLogsCount) {
            Write-Verbose -Message 'Filtering Found Flow Logs down to those targeting Virtual Networks, Subnets, and Network Interfaces.'
            [System.Array]$VNETFlowLogResourceTypes = @(
                'Microsoft.Network/virtualNetworks',
                'Microsoft.Network/virtualNetworks/subnets',
                'Microsoft.Network/networkInterfaces'
            )

            [System.Collections.ArrayList]$VNETFlowLogs = @()
            foreach ($FlowLog in $AzFlowLogs) {
                [System.String]$FlowLogTargetResourceID = $FlowLog.Properties.TargetResourceId
                if ($FlowLogTargetResourceID | Select-String -Pattern $VNETFlowLogResourceTypes) {
                    $VNETFlowLogs.Add($FlowLog) | Out-Null
                }
            }
        }

        [System.Int32]$v = 1
        [System.Int32]$VNETFlowLogsCount = $VNETFlowLogs.Count
        if (0 -lt $VNETFlowLogsCount) {
            Write-Verbose -Message "Found: '$VNETFlowLogsCount' Virtual Network Flow Logs."

            Write-Verbose -Message 'Checking VNET Flow Log state and enabling or disabling...'
            foreach ($VNETFlowLog in $VNETFlowLogs) {
                [System.Collections.ArrayList]$VNETFlowLogResourceIDArray = $VNETFlowLog.ResourceId.Split('/')
                [System.String]$NetworkWatcherResourceGroupName = $VNETFlowLogResourceIDArray[4]
                [System.String]$NetworkWatcherName = $VNETFlowLogResourceIDArray[8]
                [System.String]$VNETFlowLogName = $VNETFlowLog.Name
                [System.String]$VNETFlowLogTargetResourceID = $VNETFlowLog.Properties.targetResourceId
                [System.String]$VNETFlowLogStorageID = $VNETFlowLog.Properties.storageId

                Write-Verbose -Message "Checking Flow Log: '$VNETFlowLogName'. Log: '$v' of: '$VNETFlowLogsCount' VNET Flow Logs."
                if ($true -eq $VNETFlowLog.Properties.Enabled) {
                    if ($true -eq $VNETFlowLog.Properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled) {
                        Write-Verbose -Message "Disabling VNET Flow Logs and Traffic Analytics on Flow Log: '$VNETFlowLogName' targeting: '$VNETFlowLogTargetResourceID'."
                        Set-AzNetworkWatcherFlowLog -ResourceGroupName $NetworkWatcherResourceGroupName -NetworkWatcherName $NetworkWatcherName -Name $VNETFlowLogName -StorageId $VNETFlowLogStorageID -TargetResourceId $VNETFlowLogTargetResourceID -Enabled $false -Force -EnableTrafficAnalytics:$false | Out-Null

                    }
                    else {
                        Write-Verbose -Message "Disabling VNET Flow Logs on Flow Log: '$VNETFlowLogName' targeting: '$VNETFlowLogTargetResourceID'."
                        Set-AzNetworkWatcherFlowLog -ResourceGroupName $NetworkWatcherResourceGroupName -NetworkWatcherName $NetworkWatcherName -Name $VNETFlowLogName -StorageId $VNETFlowLogStorageID -TargetResourceId $VNETFlowLogTargetResourceID -Enabled $false -Force | Out-Null
                    }
                    Write-Verbose -Message "Disabling Flow Log: '$VNETFlowLogName' targeting: '$VNETFlowLogTargetResourceID'."
                }
                else {
                    Write-Verbose -Message "Flow Log: '$VNETFlowLogName' targeting: '$VNETFlowLogTargetResourceID' is already disabled."
                }

                $v++
            }
        }
        else {
            Write-Verbose -Message 'No Flow Logs found targeting Virtual Networks, Subnets, or Network Interfaces.'
        }

        Remove-Variable -Name VNETFlowLogs -ErrorAction SilentlyContinue
        $i++
    }
}
else {
    Write-Verbose -Message 'No Azure subscriptions found.'
}