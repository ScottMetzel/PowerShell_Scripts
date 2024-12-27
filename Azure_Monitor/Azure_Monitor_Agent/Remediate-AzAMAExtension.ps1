#Requires -Modules Az.Accounts, Az.Compute, Az.ConnectedMachine, Az.Resources
<#
    .SYNOPSIS
    This script attempts to install Microsoft's Azure Monitor Agent on servers.

    .DESCRIPTION
    This script attempts to install Microsoft's Azure Monitor Agent ("AMA") on servers.
    If the agent is missing or unhealthy, it's added to a server.
    The script works at resource group and resource scopes across the three different resource types currently supported by the AMA,
    which are Virtual Machines, Virtual Machine Scale Sets, or Arc-enabled Servers.

    It has "WhatIf" support, and reports on its findings before attempting any changes.

    This script is provided AS-IS with no warranties or claims it'll work as described. Please review the code and test in a safe environment.
    Executing this script is done at your own risk ;) .

    This script remediates missing Azure Monitor agent extensions from Azure VMs, VM Scale Sets, and Arc-enabled Servers.
    It can report on the state of the extension or add, add/remove in the event of a failed installation, or remove the extension.
    This script works at the Azure management plane. It does not directly interact with an Operating System.

    .NOTES
    ===========================================================================
    Created with: 	Microsoft Visual Studio Code
    Created on:   	12/06/2024 11:32 AM
    Created by:   	Scott Metzel
    Organization: 	-
    Filename:     	Remediate-AzAMAExtension.ps1
    ===========================================================================

    .PARAMETER ResourceGroupName
    Supply the name of a resource group. Sets the script to run at a resource group scope.

    .PARAMETER RemediateResourceTypes
    Configures the script to look for certain resource types.

    .PARAMETER ResourceID
    Supply a Resource ID for a VM, VM Scale Set, or Arc-enabled Server. Sets the script to run at a resource scope.

    .PARAMETER ProxyURLAndPort
    Configures the Azure Monitor Agent to use a proxy. Use the format "http://myproxy.mycompany.org:PortNumber".

    .PARAMETER ProxyCredential
    Supply a PSCredential Object. Configures the Azure Monitor Agent to use an authenticated proxy.

    .PARAMETER ReportDirectoryPath
    Supply a directory path to store reports in. Configures the script to report on its findings.

    .PARAMETER ReportOnly
    Configures the script to only report on its findings, and not make any state changes.

    .EXAMPLE
    Remediate-AzAMAExtension.ps1 -ResourceGroupName "MyResourceGroup" -ReportDirectoryPath "C:\Temp\" -ReportOnly

    .EXAMPLE
    Remediate-AzAMAExtension.ps1 -ResourceGroupName "MyResourceGroup" -ReportDirectoryPath "C:\Temp\" -WhatIf

    .EXAMPLE
    Remediate-AzAMAExtension.ps1 -ResourceGroupName "MyResourceGroup" -RemediateResourceTypes "VirtualMachines" -ReportDirectoryPath "C:\Temp\" -WhatIf

    .EXAMPLE
    Remediate-AzAMAExtension.ps1 -ResourceGroupName "MyResourceGroup" -RemediateResourceTypes "VirtualMachines" -ReportDirectoryPath "C:\Temp\"

    .EXAMPLE
    Remediate-AzAMAExtension.ps1 -ResourceID "/subscriptions/18939564-5bf5-4448-bd41-c261f2b7d5b2/resourceGroups/r/providers/Microsoft.HybridCompute/Machines/a" -ReportDirectoryPath "C:\Temp\" -ReportOnly

    .EXAMPLE
    Remediate-AzAMAExtension.ps1 -ResourceGroupName "MyResourceGroup" -ReportDirectoryPath "C:\Temp\" -ProxyURLAndPort "http://myproxy.org:8080"

    .EXAMPLE
    $GetProxyCredential = Get-Credential -Message "Credentials Used for Proxy?"
    Remediate-AzAMAExtension.ps1 -ResourceGroupName "MyResourceGroup" -ReportDirectoryPath "C:\Temp\" -ProxyURLAndPort "http://myproxy.org:8080" -ProxyCredential $GetProxyCredential
#>
[CmdletBinding(
    SupportsShouldProcess,
    ConfirmImpact = 'Medium'
)]

param(
    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'ResourceGroup'
    )]
    [System.String]$ResourceGroupName,
    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'ResourceID'
    )]
    [System.String]$ResourceID,
    [Parameter(
        Mandatory = $false
    )]
    [ValidateSet(
        'All',
        'VirtualMachines',
        'VirtualMachineScaleSets',
        'ArcEnabledServers'
    )]
    [System.String]$RemediateResourceTypes = 'All',
    [System.String]$ProxyURLAndPort = '',
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $ProxyCredential = [System.Management.Automation.PSCredential]::Empty,
    [System.String]$ReportDirectoryPath = '',
    [switch]$ReportOnly
)
$InformationPreference = 'Continue'
[System.String]$ScriptName = $MyInvocation.MyCommand.Name
[System.String]$ScriptNameNoExt = $ScriptName.Split('.')[0]
[System.String]$Now = Get-Date -Format FileDateTimeUniversal

Write-Information -MessageData "Starting: '$ScriptName'."
## Arc:  /subscriptions/18939564-5bf5-4448-bd41-c261f2b7d5b2/resourceGroups/r/providers/Microsoft.HybridCompute/Machines/a
## VM:   /subscriptions/18939564-5bf5-4448-bd41-c261f2b7d5b2/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/b
## VMSS: /subscriptions/18939564-5bf5-4448-bd41-c261f2b7d5b2/resourceGroups/r/providers/Microsoft.Compute/virtualMachineScaleSets/c

### BEGIN: Report Setup ###
if ($ReportDirectoryPath.Length -ge 3) {
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

### BEGIN: Proxy Configuration ###
# Test for a scenario where proxy credentials were supplied without a proxy to use
if ($PSBoundParameters.ContainsKey('ProxyCredentials') -and (!($PSBoundParameters.ContainsKey('ProxyURLAndPort')))) {
    Write-Error -Message 'Proxy credentials were supplied without a proxy to use. Did you forget something?'
    throw
}

if ($PSBoundParameters.ContainsKey('ProxyURLAndPort')) {
    Write-Information -MessageData 'Setting up script to configure proxy settings on AMA Extension.'

    # Configure proxy credentials depending on resource type and OS
    if ($PSBoundParameters.ContainsKey('ProxyCredentials')) {
        Write-Information -MessageData 'An authenticated proxy will be used.'
        # VM - Windows and Linux
        [System.String]$AMASettingsStringWindowsAndLinux = [System.String]::Concat('{"proxy":{"mode":"application","address":"', $ProxyURLAndPort, '","auth": "true"}}')
        [System.Security.SecureString]$AMAProtectedSettingsStringWindowsAndLinux = [System.String]::Concat('{"proxy":{"username":"', $ProxyCredential.UserName, '","password": "', $ProxyCredential.Password, '"}}')

        # Arc - Windows and Linux
        [System.Collections.Hashtable]$AMASettingsStringArc = @{
            'proxy' = @{
                mode    = 'application';
                address = $ProxyURLAndPort;
                auth    = 'true'
            }
        }
        [System.Collections.Hashtable]$AMAProtectedSettingsStringArc = @{
            'proxy' = @{
                username = $ProxyCredential.UserName;
                password = $ProxyCredential.Password
            }
        }
    }
    else {
        Write-Information -MessageData 'An unauthenticated proxy will be used.'
        # VM - Windows and Linux
        [System.String]$AMASettingsStringWindowsAndLinux = [System.String]::Concat('{"proxy":{"mode":"application","address":"', $ProxyURLAndPort, '","auth": "false"}}')

        # Arc - Windows and Linux
        [System.Collections.Hashtable]$AMASettingsStringArc = @{
            'proxy' = @{
                mode    = 'application';
                address = $ProxyURLAndPort;
                auth    = 'false'
            }
        }

    }
}
else {
    Write-Information -MessageData 'Setting up script to configure AMA Extension without proxy settings.'

    # VM - Windows and Linux
    [System.String]$AMASettingsStringWindowsAndLinux = '{"proxy":{"mode":"none"}}';

    # Arc - Windows and Linux
    [System.Collections.Hashtable]$AMASettingsStringArc = @{
        'proxy' = @{
            mode = 'none'
        }
    }
}
### END: Proxy Configuration ###
### BEGIN: DISCOVERY - Resource Group ###
if ($PSBoundParameters.ContainsKey('ResourceGroupName')) {
    Write-Information -MessageData "Getting resource group: '$ResourceGroupName'."

    try {
        $ErrorActionPreference = 'Stop'
        $GetAzResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName
    }
    catch {
        $_
    }

    if ($GetAzResourceGroup) {
        Write-Information -MessageData "Found resource group: '$ResourceGroupName'."
    }
    else {
        Write-Warning -Message "Could not find resource group: '$ResourceGroupName' in current context."
        throw
    }

    if ($RemediateResourceTypes -in @('All', 'VirtualMachines')) {
        Write-Information -MessageData 'Getting all Azure VMs in resource group.'
        [System.Collections.ArrayList]$AzVMsArray = @()
        Get-AzVM -ResourceGroupName $ResourceGroupName | ForEach-Object -Process {
            $AzVMsArray.Add($_) | Out-Null
        }
    }

    if ($RemediateResourceTypes -in @('All', 'VirtualMachineScaleSets')) {
        Write-Information -MessageData 'Getting all Azure VM Scale Sets in resource group.'
        [System.Collections.ArrayList]$AzVMSSsArray = @()
        Get-AzVmss -ResourceGroupName $ResourceGroupName | ForEach-Object -Process {
            $AzVMSSsArray.Add($_) | Out-Null
        }
    }

    if ($RemediateResourceTypes -in @('All', 'ArcEnabledServers')) {
        Write-Information -MessageData 'Getting all Azure Arc-enabled Servers in resource group.'
        [System.Collections.ArrayList]$AzConnectedMachinesArray = @()
        Get-AzConnectedMachine -ResourceGroupName $ResourceGroupName | ForEach-Object -Process {
            $AzConnectedMachinesArray.Add($_) | Out-Null
        }
    }

    ### BEGIN: ANALYSIS ###
    # Work with Azure VMs
    if ($RemediateResourceTypes -in @('All', 'VirtualMachines')) {
        Write-Information -MessageData '== Discovering AMA presence on VMs. =='
        [System.Int32]$AzVMsArrayCount = $AzVMsArray.Count
        if ($AzVMsArrayCount -gt 0) {
            [System.Collections.ArrayList]$AzVMsNoAMAArray = @()
            [System.Collections.ArrayList]$AzVMsAMAHealthyArray = @()
            [System.Collections.ArrayList]$AzVMsAMAUnhealthyArray = @()

            Write-Information -MessageData "Found: '$AzVMsArrayCount' Azure VMs in resource group: '$ResourceGroupName'."
            Write-Information -MessageData 'Enumerating VM array to find AMA extension.'

            [System.Int32]$i = 1
            [System.Int32]$TotalCount = $AzVMsArray.Count
            foreach ($VM in $AzVMsArray) {
                [System.String]$VMName = $VM.Name

                Write-Information -MessageData "Looking for AMA extension on VM: '$VMName' in resource group. Server: '$i' of: '$TotalCount'."
                $GetAMAExtension = $VM.Extensions | Where-Object -FilterScript {
                ($_.Name -in @('AzureMonitorWindowsAgent', 'AzureMonitorLinuxAgent')) -and ($_.Publisher -eq 'Microsoft.Azure.Monitor')
                }

                if ($GetAMAExtension) {
                    Write-Information -MessageData 'Found AMA extension on VM.'

                    [System.String]$AMAExtensionProvisioningState = $GetAMAExtension.ProvisioningState
                    if ($AMAExtensionProvisioningState -eq 'Succeeded') {
                        Write-Information -MessageData "Extension is in a: '$AMAExtensionProvisioningState' state."
                        $AzVMsAMAHealthyArray.Add($VM) | Out-Null
                    }
                    else {
                        Write-Information -MessageData "Extension is in a: '$AMAExtensionProvisioningState' state."
                        $AzVMsAMAUnhealthyArray.Add($VM) | Out-Null
                    }
                }
                else {
                    Write-Information -MessageData 'Did not find AMA extension on VM.'
                    $AzVMsNoAMAArray.Add($VM) | Out-Null
                }

                $i++
            }
        }
        else {
            Write-Information -MessageData 'Did not find any Azure VMs in resource group.'
        }
    }

    # Work with Azure VMSS
    if ($RemediateResourceTypes -in @('All', 'VirtualMachineScaleSets')) {
        Write-Information -MessageData '== Discovering AMA presence on VM Scale Sets. =='
        [System.Int32]$AzVMSSsArrayCount = $AzVMSSsArray.Count
        if ($AzVMSSsArrayCount -gt 0) {
            [System.Collections.ArrayList]$AzVMSSsNoAMAArray = @()
            [System.Collections.ArrayList]$AzVMSSsAMAHealthyArray = @()
            [System.Collections.ArrayList]$AzVMSSsAMAUnhealthyArray = @()

            Write-Information -MessageData "Found: '$AzVMSSArrayCount' Azure VM Scale Sets in resource group: '$ResourceGroupName'."
            Write-Information -MessageData 'Enumerating VMSS array to find AMA extension.'

            [System.Int32]$i = 1
            [System.Int32]$TotalCount = $AzVMSSsArray.Count
            foreach ($VMSS in $AzVMSSsArray) {
                [System.String]$VMSSName = $VMSS.Name

                Write-Information -MessageData "Looking for AMA extension on VMSS: '$VMSSName' in resource group. Server: '$i' of: '$TotalCount'."
                $GetAMAExtension = $VMSS.VirtualMachineProfile.ExtensionProfile.Extensions | Where-Object -FilterScript {
                ($_.Name -in @('AzureMonitorWindowsAgent', 'AzureMonitorLinuxAgent')) -and ($_.Publisher -eq 'Microsoft.Azure.Monitor')
                }

                if ($GetAMAExtension) {
                    Write-Information -MessageData 'Found AMA extension on VMSS.'

                    [System.String]$AMAExtensionProvisioningState = $GetAMAExtension.ProvisioningState
                    if ($AMAExtensionProvisioningState -eq 'Succeeded') {
                        Write-Information -MessageData "Extension is in a: '$AMAExtensionProvisioningState' state."
                        $AzVMSSsAMAHealthyArray.Add($VMSS) | Out-Null
                    }
                    else {
                        Write-Information -MessageData "Extension is in a: '$AMAExtensionProvisioningState' state."
                        $AzVMSSsAMAUnhealthyArray.Add($VMSS) | Out-Null
                    }
                }
                else {
                    Write-Information -MessageData 'Did not find AMA extension on VMSS.'
                    $AzVMSSsNoAMAArray.Add($VMSS) | Out-Null
                }
            }
        }
        else {
            Write-Information -MessageData 'Did not find any Azure VM Scale Sets in resource group.'
        }
    }
    # Work with Azure Arc-enabled Servers
    if ($RemediateResourceTypes -in @('All', 'ArcEnabledServers')) {
        Write-Information -MessageData '== Discovering AMA presence on Arc-enabled Servers. =='
        [System.Int32]$AzConnectedMachinesArrayCount = $AzConnectedMachinesArray.Count
        if ($AzConnectedMachinesArrayCount -gt 0) {
            [System.Collections.ArrayList]$AzConnectedMachinesNoAMAArray = @()
            [System.Collections.ArrayList]$AzConnectedMachinesAMAHealthyArray = @()
            [System.Collections.ArrayList]$AzConnectedMachinesAMAUnhealthyArray = @()
            [System.Collections.ArrayList]$AzConnectedMachinesNotConnectedArray = @()

            Write-Information -MessageData "Found: '$AzConnectedMachinesArrayCount' Azure Arc-enabled Servers in resource group: '$ResourceGroupName'."
            Write-Information -MessageData 'Enumerating Arc-enabled Servers array to find AMA extension.'

            [System.Int32]$i = 1
            [System.Int32]$TotalCount = $AzConnectedMachinesArray.Count
            foreach ($ConnectedMachine in $AzConnectedMachinesArray) {
                [System.String]$ConnectedMachineResourceGroupName = $ConnectedMachine.ResourceGroupName
                [System.String]$ConnectedMachineName = $ConnectedMachine.Name

                Write-Information -MessageData "Looking for AMA extension on Arc-enabled Server: '$ConnectedMachineName' in resource group. Server: '$i' of: '$TotalCount'."
                $GetAMAExtension = Get-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachineResourceGroupName -MachineName $ConnectedMachineName | Where-Object -FilterScript {
                ($_.Name -in @('AzureMonitorWindowsAgent', 'AzureMonitorLinuxAgent')) -and ($_.Publisher -eq 'Microsoft.Azure.Monitor')
                }

                if ('Connected' -eq $ConnectedMachine.Status) {
                    Write-Information -MessageData 'Arc-enabled Server is connected.'

                    if ($GetAMAExtension) {
                        Write-Information -MessageData 'Found AMA extension on Arc-enabled Server.'

                        [System.String]$AMAExtensionProvisioningState = $GetAMAExtension.ProvisioningState
                        if ($AMAExtensionProvisioningState -eq 'Succeeded') {
                            Write-Information -MessageData "Extension is in a: '$AMAExtensionProvisioningState' state."
                            $AzConnectedMachinesAMAHealthyArray.Add($ConnectedMachine) | Out-Null
                        }
                        else {
                            Write-Information -MessageData "Extension is in a: '$AMAExtensionProvisioningState' state."
                            $AzConnectedMachinesAMAUnhealthyArray.Add($ConnectedMachine) | Out-Null
                        }
                    }
                    else {
                        Write-Information -MessageData 'Did not find AMA extension on Arc-enabled Server.'
                        $AzConnectedMachinesNoAMAArray.Add($ConnectedMachine) | Out-Null
                    }
                }
                else {
                    Write-Warning -Message "Arc-enabled Server: '$ConnectedMachineName' is not connected."
                    $AzConnectedMachinesNotConnectedArray.Add($ConnectedMachine) | Out-Null
                }

                $i++
            }
        }
        else {
            Write-Information -MessageData 'Did not find any Arc-enabled Servers in resource group.'
        }
    }
    ### END: ANALYSIS ###
    ### END: DISCOVERY ###

    ### BEGIN: REPORT ###
    ### Test Report Directory validity and normalize provided parameter value
    if ($ReportDirectoryPath.Length -ge 3) {
        # VMs
        if ($RemediateResourceTypes -in @('All', 'VirtualMachines')) {
            Write-Information -MessageData 'Creating current-state report names for VMs.'
            [System.String]$AzVMsNoAMAReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'VMs', '_No-AMA_', $Now, '.csv')
            [System.String]$AzVMsNoAMAReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzVMsNoAMAReportFileName)
            [System.String]$AzVMsAMAHealthyReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'VMs', '_AMA-Healthy_', $Now, '.csv')
            [System.String]$AzVMsAMAHealthyReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzVMsAMAHealthyReportFileName)
            [System.String]$AzVMsAMAUnhealthyReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'VMs', '_AMA-Unhealthy_', $Now, '.csv')
            [System.String]$AzVMsAMAUnhealthyReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzVMsAMAUnhealthyReportFileName)

            if ($AzVMsNoAMAArray.Count -ge 1) {
                Write-Information -MessageData "Exporting report of VMs without AMA to: '$AzVMsNoAMAReportFilePath'."
                if ($PSCmdlet.ShouldProcess($AzVMsNoAMAReportFilePath)) {
                    $AzVMsNoAMAArray | Export-Csv -LiteralPath $AzVMsNoAMAReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                }
                else {
                    $AzVMsNoAMAArray | Export-Csv -LiteralPath $AzVMsNoAMAReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                }
            }
            else {
                Write-Information -MessageData 'No VMs without AMA to report.'
            }

            if ($AzVMsAMAHealthyArray.Count -ge 1) {
                Write-Information -MessageData "Exporting report of VMs with AMA in a healthy state to: '$AzVMsAMAHealthyReportFilePath'."
                if ($PSCmdlet.ShouldProcess($AzVMsAMAHealthyReportFilePath)) {
                    $AzVMsAMAHealthyArray | Export-Csv -LiteralPath $AzVMsAMAHealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                }
                else {
                    $AzVMsAMAHealthyArray | Export-Csv -LiteralPath $AzVMsAMAHealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                }
            }
            else {
                Write-Information -MessageData 'No VMs with AMA in a healthy state to report.'
            }

            if ($AzVMsAMAUnhealthyArray.Count -ge 1) {
                Write-Information -MessageData "Exporting report of VMs with AMA in an unhealthy state to: '$AzVMsAMAUnhealthyReportFilePath'."
                if ($PSCmdlet.ShouldProcess($AzVMsAMAUnhealthyReportFilePath)) {
                    $AzVMsAMAUnhealthyArray | Export-Csv -LiteralPath $AzVMsAMAUnhealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                }
                else {
                    $AzVMsAMAUnhealthyArray | Export-Csv -LiteralPath $AzVMsAMAUnhealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                }
            }
            else {
                Write-Information -MessageData 'No VMs with AMA in an unhealthy state to report.'
            }
        }
        # VMSS
        if ($RemediateResourceTypes -in @('All', 'VirtualMachineScaleSets')) {
            Write-Information -MessageData 'Creating current-state report names for VM Scale Sets.'
            [System.String]$AzVMSSsNoAMAReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'VMSSs', '_No-AMA_', $Now, '.csv')
            [System.String]$AzVMSSsNoAMAReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzVMSSsNoAMAReportFileName)
            [System.String]$AzVMSSsAMAHealthyReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'VMSSs', '_AMA-Healthy_', $Now, '.csv')
            [System.String]$AzVMSSsAMAHealthyReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzVMSSsAMAHealthyReportFileName)
            [System.String]$AzVMSSsAMAUnhealthyReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'VMSSs', '_AMA-Unhealthy_', $Now, '.csv')
            [System.String]$AzVMSSsAMAUnhealthyReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzVMSSsAMAUnhealthyReportFileName)

            if ($AzVMSSsNoAMAArray.Count -ge 1) {
                Write-Information -MessageData "Exporting report of VM Scale Sets without AMA to: '$AzVMSSsNoAMAReportFilePath'."
                if ($PSCmdlet.ShouldProcess($AzVMSSsNoAMAReportFilePath)) {
                    $AzVMSSsNoAMAArray | Export-Csv -LiteralPath $AzVMSSsNoAMAReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                }
                else {
                    $AzVMSSsNoAMAArray | Export-Csv -LiteralPath $AzVMSSsNoAMAReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                }
            }
            else {
                Write-Information -MessageData 'No VM Scale Sets without AMA to report.'
            }

            if ($AzVMSSsAMAHealthyArray.Count -ge 1) {
                Write-Information -MessageData "Exporting report of VM Scale Sets with AMA in a healthy state to: '$AzVMSSsAMAHealthyReportFilePath'."
                if ($PSCmdlet.ShouldProcess($AzVMSSsAMAHealthyReportFilePath)) {
                    $AzVMSSsAMAHealthyArray | Export-Csv -LiteralPath $AzVMSSsAMAHealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                }
                else {
                    $AzVMSSsAMAHealthyArray | Export-Csv -LiteralPath $AzVMSSsAMAHealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                }
            }
            else {
                Write-Information -MessageData 'No VM Scale Sets with AMA in a healthy state to report.'
            }

            if ($AzVMSSsAMAUnhealthyArray.Count -ge 1) {
                Write-Information -MessageData "Exporting report of VM Scale Sets with AMA in an unhealthy state to: '$AzVMSSsAMAUnhealthyReportFilePath'."
                if ($PSCmdlet.ShouldProcess($AzVMSSsAMAUnhealthyReportFilePath)) {
                    $AzVMSSsAMAUnhealthyArray | Export-Csv -LiteralPath $AzVMSSsAMAUnhealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                }
                else {
                    $AzVMSSsAMAUnhealthyArray | Export-Csv -LiteralPath $AzVMSSsAMAUnhealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                }
            }
            else {
                Write-Information -MessageData 'No VM Scale Sets with AMA in an unhealthy state to report.'
            }
        }
        # Arc-enabled Servers
        if ($RemediateResourceTypes -in @('All', 'ArcEnabledServers')) {
            Write-Information -MessageData 'Creating current-state report names for Arc-enabled Servers.'
            [System.String]$AzConnectedMachinesNoAMAReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'Arc', '_No-AMA_', $Now, '.csv')
            [System.String]$AzConnectedMachinesNoAMAReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzConnectedMachinesNoAMAReportFileName)
            [System.String]$AzConnectedMachinesAMAHealthyReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'Arc', '_AMA-Healthy_', $Now, '.csv')
            [System.String]$AzConnectedMachinesAMAHealthyReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzConnectedMachinesAMAHealthyReportFileName)
            [System.String]$AzConnectedMachinesAMAUnhealthyReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'Arc', '_AMA-Unhealthy_', $Now, '.csv')
            [System.String]$AzConnectedMachinesAMAUnhealthyReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzConnectedMachinesAMAUnhealthyReportFileName)
            [System.String]$AzConnectedMachinesNotConnectedReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'Arc', '_Not-Connected_', $Now, '.csv')
            [System.String]$AzConnectedMachinesNotConnectedReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzConnectedMachinesNotConnectedReportFileName)

            if ($AzConnectedMachinesNoAMAArray.Count -ge 1) {
                Write-Information -MessageData "Exporting report of Arc-enabled Servers without AMA to: '$AzConnectedMachinesNoAMAReportFilePath'."
                if ($PSCmdlet.ShouldProcess($AzConnectedMachinesNoAMAReportFilePath)) {
                    $AzConnectedMachinesNoAMAArray | Export-Csv -LiteralPath $AzConnectedMachinesNoAMAReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                }
                else {
                    $AzConnectedMachinesNoAMAArray | Export-Csv -LiteralPath $AzConnectedMachinesNoAMAReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                }
            }
            else {
                Write-Information -MessageData 'No Arc-enabled Servers without AMA to report.'
            }

            if ($AzConnectedMachinesAMAHealthyArray.Count -ge 1) {
                Write-Information -MessageData "Exporting report of Arc-enabled Servers with AMA in a healthy state to: '$AzConnectedMachinesAMAHealthyReportFilePath'."
                if ($PSCmdlet.ShouldProcess($AzConnectedMachinesAMAHealthyReportFilePath)) {
                    $AzConnectedMachinesAMAHealthyArray | Export-Csv -LiteralPath $AzConnectedMachinesAMAHealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                }
                else {
                    $AzConnectedMachinesAMAHealthyArray | Export-Csv -LiteralPath $AzConnectedMachinesAMAHealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                }
            }
            else {
                Write-Information -MessageData 'No Arc-enabled Servers with AMA in a healthy state to report.'
            }

            if ($AzConnectedMachinesAMAUnhealthyArray.Count -ge 1) {
                Write-Information -MessageData "Exporting report of Arc-enabled Servers with AMA in an unhealthy state to: '$AzConnectedMachinesAMAUnhealthyReportFilePath'."
                if ($PSCmdlet.ShouldProcess($AzConnectedMachinesAMAUnhealthyReportFilePath)) {
                    $AzConnectedMachinesAMAUnhealthyArray | Export-Csv -LiteralPath $AzConnectedMachinesAMAUnhealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                }
                else {
                    $AzConnectedMachinesAMAUnhealthyArray | Export-Csv -LiteralPath $AzConnectedMachinesAMAUnhealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                }
            }
            else {
                Write-Information -MessageData 'No Arc-enabled Servers with AMA in an unhealthy state to report.'
            }

            if ($AzConnectedMachinesNotConnectedArray.Count -ge 1) {
                Write-Information -MessageData "Exporting report of Arc-enabled Servers which are not connected to: '$AzConnectedMachinesNotConnectedReportFilePath'."
                if ($PSCmdlet.ShouldProcess($AzConnectedMachinesNotConnectedReportFilePath)) {
                    $AzConnectedMachinesNotConnectedArray | Export-Csv -LiteralPath $AzConnectedMachinesNotConnectedReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                }
                else {
                    $AzConnectedMachinesNotConnectedArray | Export-Csv -LiteralPath $AzConnectedMachinesNotConnectedReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                }
            }
            else {
                Write-Information -MessageData 'No Arc-enabled Server which is not connected to report.'
            }
        }
    }
    ### END: REPORT ###
    ### BEGIN: REMEDIATION ###
    Write-Information -MessageData '== Starting remediation phase =='
    if (!($PSBoundParameters.ContainsKey('ReportOnly'))) {

        ### BEGIN: REMEDIATION - VMs with an Unhealthy AMA ###
        #### This section attempts to remove the AMA from the resource and then adds that resource to the array of resources without AMA.
        #### Ideally duplicative remedation code would be in a function... will optimize later.
        if ($RemediateResourceTypes -in @('All', 'VirtualMachines')) {
            if ($AzVMsAMAUnhealthyArray.Count -ge 1) {
                Write-Information -MessageData 'Working on removing AMA from VMs with an unhealthy agent before attempting to reinstall.'

                [System.Int32]$i = 1
                [System.Int32]$TotalCount = $AzVMsAMAUnhealthyArray.Count
                foreach ($VM in $AzVMsAMAUnhealthyArray) {
                    [System.String]$VMName = $VM.Name

                    # VM - Windows
                    if ($null -ne $VM.OSProfile.WindowsConfiguration) {
                        Write-Information -MessageData "Attempting to uninstall AMA for Windows for VM: '$VMName'. Server: '$i' of: '$TotalCount'."

                        try {
                            $ErrorActionPreference = 'Stop'
                            if ($PSCmdlet.ShouldProcess($VMName)) {
                                Remove-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -VMName $VMName -Name AzureMonitorWindowsAgent

                                Write-Information -MessageData "Adding VM: '$VMName' to array of VMs without AMA for reinstallation."
                                $AzVMsNoAMAArray.Add($VM) | Out-Null
                            }
                            else {
                                Remove-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -VMName $VMName -Name AzureMonitorWindowsAgent -WhatIf
                            }
                        }
                        catch {
                            $_
                        }
                    }
                    # VM - Linux
                    elseif ($null -ne $VM.OSProfile.LinuxConfiguration) {
                        Write-Information -MessageData "Attempting to uninstall AMA for Linux for VM: '$VMName'. Server: '$i' of: '$TotalCount'."

                        try {
                            $ErrorActionPreference = 'Stop'
                            if ($PSCmdlet.ShouldProcess($VMName)) {
                                Remove-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -VMName $VMName -Name AzureMonitorLinuxAgent

                                Write-Information -MessageData "Adding VM: '$VMName' to array of VMs without AMA for reinstallation."
                                $AzVMsNoAMAArray.Add($VM) | Out-Null
                            }
                            else {
                                Remove-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -VMName $VMName -Name AzureMonitorLinuxAgent -WhatIf
                            }
                        }
                        catch {
                            $_
                        }
                    }
                    else {
                        Write-Information -MessageData "The OS Profile configuration for VM: '$VMName' is unrecognized. Moving on."
                    }

                    $i++
                }
            }
            else {
                Write-Information -MessageData 'No VMs with an unhealthy AMA to uninstall.'
            }
        }
        ### END: REMEDIATION - VMs with an Unhealthy AMA ###

        ### BEGIN: REMEDIATION - VMSSs with an Unhealthy AMA ###
        #### This section attempts to remove the AMA from the resource and then adds that resource to the array of resources without AMA.
        #### Ideally duplicative remedation code would be in a function... will optimize later.
        if ($RemediateResourceTypes -in @('All', 'VirtualMachineScaleSets')) {
            if ($AzVMSSsAMAUnhealthyArray.Count -ge 1) {
                Write-Information -MessageData 'Working on removing AMA from VM Scale Sets with an unhealthy agent before attempting to reinstall.'

                [System.Int32]$i = 1
                [System.Int32]$TotalCount = $AzVMSSsAMAUnhealthyArray.Count
                foreach ($VMSS in $AzVMSSsAMAUnhealthyArray) {
                    [System.String]$VMSSName = $VMSS.Name

                    # VMSS - Windows
                    if ($null -ne $VMSS.OSProfile.WindowsConfiguration) {
                        Write-Information -MessageData "Attempting to uninstall AMA for Windows for VMSS: '$VMSSName'. Server: '$i' of: '$TotalCount'."

                        try {
                            $ErrorActionPreference = 'Stop'
                            if ($PSCmdlet.ShouldProcess($VMSSName)) {
                                Remove-AzVmssExtension -VirtualMachineScaleSet $VMSS -Name AzureMonitorWindowsAgent

                                Write-Information -MessageData "Adding VM Scale Set: '$VMSSName' to array of VM Scale Sets without AMA for reinstallation."
                                $AzVMSSsNoAMAArray.Add($VMSS) | Out-Null
                            }
                            else {
                                Remove-AzVmssExtension -VirtualMachineScaleSet $VMSS -Name AzureMonitorWindowsAgent -WhatIf
                            }
                        }
                        catch {
                            $_
                        }
                    }
                    # VMSS - Linux
                    elseif ($null -ne $VMSS.OSProfile.LinuxConfiguration) {
                        Write-Information -MessageData "Attempting to uninstall AMA for Linux for VMSS: '$VMSSName'. Server: '$i' of: '$TotalCount'."

                        try {
                            $ErrorActionPreference = 'Stop'
                            if ($PSCmdlet.ShouldProcess($VMSSName)) {
                                Remove-AzVmssExtension -VirtualMachineScaleSet $VMSS -Name AzureMonitorLinuxAgent

                                Write-Information -MessageData "Adding VM Scale Set: '$VMSSName' to array of VM Scale Sets without AMA for reinstallation."
                                $AzVMSSsNoAMAArray.Add($VMSS) | Out-Null
                            }
                            else {
                                Remove-AzVmssExtension -VirtualMachineScaleSet $VMSS -Name AzureMonitorLinuxAgent -WhatIf
                            }
                        }
                        catch {
                            $_
                        }
                    }
                    else {
                        Write-Information -MessageData "The OS Profile configuration for VM: '$VMName' is unrecognized. Moving on."
                    }
                    $i++
                }
            }
            else {
                Write-Information -MessageData 'No VM Scale Sets with an unhealthy AMA to uninstall.'
            }
        }
        ### END: REMEDIATION - VMSSs with an Unhealthy AMA ###

        ### BEGIN: REMEDIATION - Arc with an Unhealthy AMA ###
        #### This section attempts to remove the AMA from the resource and then adds that resource to the array of resources without AMA.
        #### Ideally duplicative remedation code would be in a function... will optimize later.
        if ($RemediateResourceTypes -in @('All', 'ArcEnabledServers')) {
            if ($AzConnectedMachinesAMAUnhealthyArray.Count -ge 1) {
                Write-Information -MessageData 'Working on removing AMA from Arc-enabled Servers with an unhealthy agent before attempting to reinstall.'

                [System.Int32]$i = 1
                [System.Int32]$TotalCount = $AzConnectedMachinesAMAUnhealthyArray.Count
                foreach ($ConnectedMachine in $AzConnectedMachinesAMAUnhealthyArray) {
                    [System.String]$ConnectedMachineName = $ConnectedMachine.Name

                    # Arc - Windows
                    if ('windows' -eq $ConnectedMachine.OSType) {
                        Write-Information -MessageData "Attempting to uninstall AMA for Windows for Arc-enabled Server: '$ConnectedMachineName'. Server: '$i' of: '$TotalCount'."

                        try {
                            $ErrorActionPreference = 'Stop'
                            if ($PSCmdlet.ShouldProcess($ConnectedMachineName)) {
                                Remove-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Name AzureMonitorWindowsAgent

                                Write-Information -MessageData "Adding Arc-enabled Server: '$ConnectedMachineName' to array of Arc-enabled Servers without AMA for reinstallation."
                                $AzConnectedMachinesNoAMAArray.Add($ConnectedMachine) | Out-Null
                            }
                            else {
                                Remove-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Name AzureMonitorWindowsAgent -WhatIf
                            }
                        }
                        catch {
                            $_
                        }
                    }
                    # Arc - Linux
                    elseif ('linux' -eq $ConnectedMachine.OSType) {
                        Write-Information -MessageData "Attempting to uninstall AMA for Linux for Arc-enabled Server: '$ConnectedMachineName'. Server: '$i' of: '$TotalCount'."

                        try {
                            $ErrorActionPreference = 'Stop'
                            if ($PSCmdlet.ShouldProcess($ConnectedMachineName)) {
                                Remove-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Name AzureMonitorLinuxAgent

                                Write-Information -MessageData "Adding Arc-enabled Server: '$ConnectedMachineName' to array of Arc-enabled Servers without AMA for reinstallation."
                                $AzConnectedMachinesNoAMAArray.Add($ConnectedMachine) | Out-Null
                            }
                            else {
                                Remove-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Name AzureMonitorLinuxAgent -WhatIf
                            }
                        }
                        catch {
                            $_
                        }
                    }
                    else {
                        Write-Information -MessageData "The OS Profile configuration for Arc-enabled Server: '$ConnectedMachineName' is unrecognized. Moving on."
                    }
                    $i++
                }
            }
            else {
                Write-Information -MessageData 'No Arc-enabled Servers with an unhealthy AMA to uninstall.'
            }
        }
        ### END: REMEDIATION - Arc with an Unhealthy AMA ###
        ### BEGIN: REMEDIATION - AMA Installation - VMs ###
        if ($RemediateResourceTypes -in @('All', 'VirtualMachines')) {
            if ($AzVMsNoAMAArray.Count -ge 1) {
                Write-Information -MessageData 'Working on remediating VMs without AMA or those which had an unhealthy AMA.'

                [System.Int32]$i = 1
                [System.Int32]$TotalCount = $AzVMsNoAMAArray.Count
                foreach ($VM in $AzVMsNoAMAArray) {
                    [System.String]$VMName = $VM.Name
                    ## VM - Windows
                    if ($null -ne $VM.OSProfile.WindowsConfiguration) {
                        Write-Information -MessageData "Attempting to add AMA for Windows for VM: '$VMName'. Server: '$i' of: '$TotalCount'."
                        try {
                            $ErrorActionPreference = 'Stop'

                            if ($PSBoundParameters.ContainsKey('ProxyURLAndPort') -and $PSBoundParameters.ContainsKey('ProxyCredential')) {
                                Write-Information -MessageData '... using an authenticated proxy.'
                                if ($PSCmdlet.ShouldProcess($VMName)) {
                                    $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorWindowsAgent' -SettingString $AMASettingsStringWindowsAndLinux -ProtectedSettingString $AMAProtectedSettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                }
                                else {
                                    $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorWindowsAgent' -SettingString $AMASettingsStringWindowsAndLinux -ProtectedSettingString $AMAProtectedSettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                }
                            }
                            elseif ($PSBoundParameters.ContainsKey('ProxyURLAndPort')) {
                                Write-Information -MessageData '... using an unauthenticated proxy.'

                                if ($PSCmdlet.ShouldProcess($VMName)) {
                                    $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorWindowsAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                }
                                else {
                                    $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorWindowsAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                }
                            }
                            else {
                                Write-Information -MessageData '... without a proxy.'

                                if ($PSCmdlet.ShouldProcess($VMName)) {
                                    $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorWindowsAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                }
                                else {
                                    $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorWindowsAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                }
                            }
                        }
                        catch {
                            $_
                        }
                    }
                    ## VM - Linux
                    elseif ($null -ne $VM.OSProfile.LinuxConfiguration) {
                        Write-Information -MessageData "Attempting to add AMA for Linux for VM: '$VMName'. Server: '$i' of: '$TotalCount'."
                        try {
                            $ErrorActionPreference = 'Stop'

                            if ($PSBoundParameters.ContainsKey('ProxyURLAndPort') -and $PSBoundParameters.ContainsKey('ProxyCredential')) {
                                Write-Information -MessageData '... using an authenticated proxy.'
                                if ($PSCmdlet.ShouldProcess($VMName)) {
                                    $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorLinuxAgent' -SettingString $AMASettingsStringWindowsAndLinux -ProtectedSettingString $AMAProtectedSettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                }
                                else {
                                    $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorLinuxAgent' -SettingString $AMASettingsStringWindowsAndLinux -ProtectedSettingString $AMAProtectedSettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                }
                            }
                            elseif ($PSBoundParameters.ContainsKey('ProxyURLAndPort')) {
                                Write-Information -MessageData '... using an unauthenticated proxy.'

                                if ($PSCmdlet.ShouldProcess($VMName)) {
                                    $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorLinuxAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                }
                                else {
                                    $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorLinuxAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                }
                            }
                            else {
                                Write-Information -MessageData '... without a proxy.'

                                if ($PSCmdlet.ShouldProcess($VMName)) {
                                    $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorLinuxAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                }
                                else {
                                    $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorLinuxAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                }
                            }
                        }
                        catch {
                            $_
                        }
                    }
                    ## VM - Undetermined
                    else {
                        Write-Information -MessageData "The VM OS Profile configuration for VM: '$VMName' is unrecognized. Moving on."
                    }

                    $i++
                }
            }
            else {
                Write-Information -MessageData 'No VMs missing AMA to remediate.'
            }
        }
        ### END: REMEDIATION - AMA Installation - VMs ###

        ### BEGIN: REMEDIATION - AMA Installation - VMSSs ###
        if ($RemediateResourceTypes -in @('All', 'VirtualMachineScaleSets')) {
            if ($AzVMSSsNoAMAArray.Count -ge 1) {
                Write-Information -MessageData 'Working on remediating VM Scale Sets without AMA or those which had an unhealthy AMA.'

                [System.Int32]$i = 1
                [System.Int32]$TotalCount = $AzVMSSsNoAMAArray.Count
                foreach ($VMSS in $AzVMSSsNoAMAArray) {
                    [System.String]$VMSSName = $VMSS.Name
                    ## VMSS - Windows
                    if ($null -ne $VMSS.OSProfile.WindowsConfiguration) {
                        Write-Information -MessageData "Attempting to add AMA for Windows for VM Scale Set: '$VMSSName'. Server: '$i' of: '$TotalCount'."
                        try {
                            $ErrorActionPreference = 'Stop'

                            if ($PSBoundParameters.ContainsKey('ProxyURLAndPort') -and $PSBoundParameters.ContainsKey('ProxyCredential')) {
                                Write-Information -MessageData '... using an authenticated proxy.'
                                if ($PSCmdlet.ShouldProcess($VMName)) {
                                    Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringWindowsAndLinux -ProtectedSetting $AMAProtectedSettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                }
                                else {
                                    Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringWindowsAndLinux -ProtectedSetting $AMAProtectedSettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                }
                            }
                            elseif ($PSBoundParameters.ContainsKey('ProxyURLAndPort')) {
                                Write-Information -MessageData '... using an unauthenticated proxy.'

                                if ($PSCmdlet.ShouldProcess($VMName)) {
                                    Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                }
                                else {
                                    Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                }
                            }
                            else {
                                Write-Information -MessageData '... without a proxy.'

                                if ($PSCmdlet.ShouldProcess($VMName)) {
                                    Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                }
                                else {
                                    Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                }
                            }
                        }
                        catch {
                            $_
                        }
                    }
                    ## VMSS - Linux
                    elseif ($null -ne $VMSS.OSProfile.LinuxConfiguration) {
                        Write-Information -MessageData "Attempting to add AMA for Linux for VM Scale Set: '$VMSSName'. Server: '$i' of: '$TotalCount'."
                        try {
                            $ErrorActionPreference = 'Stop'

                            if ($PSBoundParameters.ContainsKey('ProxyURLAndPort') -and $PSBoundParameters.ContainsKey('ProxyCredential')) {
                                Write-Information -MessageData '... using an authenticated proxy.'
                                if ($PSCmdlet.ShouldProcess($VMSSName)) {
                                    Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -ProtectedSetting $AMAProtectedSettingsStringWindowsAndLinux
                                }
                                else {
                                    Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -ProtectedSetting $AMAProtectedSettingsStringWindowsAndLinux -WhatIf
                                }
                            }
                            elseif ($PSBoundParameters.ContainsKey('ProxyURLAndPort')) {
                                Write-Information -MessageData '... using an unauthenticated proxy.'

                                if ($PSCmdlet.ShouldProcess($VMSSName)) {
                                    Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                }
                                else {
                                    Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                }
                            }
                            else {
                                Write-Information -MessageData '... without a proxy.'

                                if ($PSCmdlet.ShouldProcess($VMSSName)) {
                                    Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                }
                                else {
                                    Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                }
                            }
                        }
                        catch {
                            $_
                        }
                    }
                    ## VMSS - Undetermined
                    else {
                        Write-Information -MessageData "The OS Profile configuration for VM Scale Set: '$VMSSName' is unrecognized. Moving on."
                    }

                    $i++
                }
            }
            else {
                Write-Information -MessageData 'No VM Scale Sets missing AMA to remediate.'
            }
        }
        ### END: REMEDIATION - AMA Installation - VMSSs ###

        ### BEGIN: REMEDIATION - AMA Installation - Arc ###
        if ($RemediateResourceTypes -in @('All', 'ArcEnabledServers')) {
            if ($AzConnectedMachinesNoAMAArray.Count -ge 1) {
                Write-Information -MessageData 'Working on remediating Arc-enabled Servers without AMA or those which had an unhealthy AMA.'

                [System.Int32]$i = 1
                [System.Int32]$TotalCount = $AzConnectedMachinesNoAMAArray.Count
                foreach ($ConnectedMachine in $AzConnectedMachinesNoAMAArray) {
                    [System.String]$ConnectedMachineName = $ConnectedMachine.Name
                    ## Arc - Windows
                    if ('windows' -eq $ConnectedMachine.OSType) {
                        Write-Information -MessageData "Attempting to add AMA for Windows for Arc-enabled Server: '$ConnectedMachineName'. Server: '$i' of: '$TotalCount'."
                        try {
                            $ErrorActionPreference = 'Stop'

                            if ($PSBoundParameters.ContainsKey('ProxyURLAndPort') -and $PSBoundParameters.ContainsKey('ProxyCredential')) {
                                Write-Information -MessageData '... using an authenticated proxy.'
                                if ($PSCmdlet.ShouldProcess($ConnectedMachineName)) {
                                    New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringArc -ProtectedSetting $AMAProtectedSettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade
                                }
                                else {
                                    New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringArc -ProtectedSetting $AMAProtectedSettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade -WhatIf
                                }
                            }
                            elseif ($PSBoundParameters.ContainsKey('ProxyURLAndPort')) {
                                Write-Information -MessageData '... using an unauthenticated proxy.'

                                if ($PSCmdlet.ShouldProcess($ConnectedMachineName)) {
                                    New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade
                                }
                                else {
                                    New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade -WhatIf
                                }
                            }
                            else {
                                Write-Information -MessageData '... without a proxy.'

                                if ($PSCmdlet.ShouldProcess($ConnectedMachineName)) {
                                    New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade
                                }
                                else {
                                    New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade -WhatIf
                                }
                            }
                        }
                        catch {
                            $_
                        }
                    }
                    ## Arc - Linux
                    elseif ('linux' -eq $ConnectedMachine.OSType) {
                        Write-Information -MessageData "Attempting to add AMA for Linux for Arc-enabled Server: '$ConnectedMachineName'. Server: '$i' of: '$TotalCount'."
                        try {
                            $ErrorActionPreference = 'Stop'

                            if ($PSBoundParameters.ContainsKey('ProxyURLAndPort') -and $PSBoundParameters.ContainsKey('ProxyCredential')) {
                                Write-Information -MessageData '... using an authenticated proxy.'
                                if ($PSCmdlet.ShouldProcess($ConnectedMachineName)) {
                                    New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringArc -ProtectedSetting $AMAProtectedSettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade
                                }
                                else {
                                    New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringArc -ProtectedSetting $AMAProtectedSettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade -WhatIf
                                }
                            }
                            elseif ($PSBoundParameters.ContainsKey('ProxyURLAndPort')) {
                                Write-Information -MessageData '... using an unauthenticated proxy.'

                                if ($PSCmdlet.ShouldProcess($ConnectedMachineName)) {
                                    New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade
                                }
                                else {
                                    New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade -WhatIf
                                }
                            }
                            else {
                                Write-Information -MessageData '... without a proxy.'

                                if ($PSCmdlet.ShouldProcess($ConnectedMachineName)) {
                                    New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade
                                }
                                else {
                                    New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade -WhatIf
                                }
                            }
                        }
                        catch {
                            $_
                        }
                    }
                    ## Arc - Undetermined
                    else {
                        Write-Information -MessageData "The OS Profile configuration for Arc-enabled Server: '$ConnectedMachineName' is unrecognized. Moving on."
                    }

                    $i++
                }
            }
            else {
                Write-Information -MessageData 'No Arc-enabled Servers missing AMA to remediate.'
            }
        }
        ### END: REMEDIATION - AMA Installation - Arc ###
    }
    else {
        Write-Information -MessageData 'Script is running in report only mode. Not remediating.'
    }
    ### END: REMEDIATION ###
}
### BEGIN: Resource ID ###
elseif ($PSBoundParameters.ContainsKey('ResourceID')) {
    Write-Information -MessageData 'Working on a single resource.'
    # A valid Resource ID's length should be greater than or equal to 113 characters, and when split into an array, consist of 9 elements.
    [System.Collections.ArrayList]$ResourceIDArray = $ResourceID.Split('/')
    if (($ResourceID.Length -ge 113) -and ($ResourceIDArray.Count -eq 9)) {

        # Get the current context for use later
        $GetAzContext = Get-AzContext
        [System.String]$AzContextSubscriptionID = $GetAzContext.Subscription.Id
        [System.String]$ResourceIDSubscriptionID = $ResourceIDArray[2]
        [System.String]$ResourceGroupName = $ResourceIDArray[4]

        # Validate the split array and subscription ID is a GUID
        if ([System.Guid]::Parse($ResourceIDSubscriptionID)) {
            Write-Information -MessageData 'Validated the parsed subscription ID is a GUID.'
        }
        else {
            Write-Error -Message "Parsed subscription ID: '$ResourceIDSubscriptionID' is not a GUID. Please try again."
            throw
        }

        # Check and switch contexts if needed
        if ($AzContextSubscriptionID -eq $ResourceIDSubscriptionID) {
            Write-Information -MessageData 'Current context matches context of supplied Resource ID.'
        }
        else {
            Write-Information -MessageData "Attempting to switch context to Azure Subscription with ID: '$ResourceIDSubscriptionID' to match context of supplied Resource ID."

            try {
                $ErrorActionPreference = 'Stop'
                Get-AzSubscription -SubscriptionId $ResourceIDSubscriptionID | Select-AzSubscription
            }
            catch {
                $_
            }
        }

        # Find the resource
        try {
            $ErrorActionPreference = 'Stop'

            $GetAzResource = Get-AzResource -ResourceId $ResourceID
            if ($GetAzResource) {
                [System.String]$ResourceName = $GetAzResource.Name
                Write-Information -MessageData "Found resource: '$ResourceName'."
            }
            else {
                Write-Warning -Message "Did not find resource with Resource ID: '$ResourceID'."
            }
        }
        catch {
            $_
        }

        # Get the resource type
        [System.String]$ResourceType = $GetAzResource.Type
        [System.Collections.ArrayList]$ValidResourceTypes = @(
            'Microsoft.Compute/virtualMachines',
            'Microsoft.Compute/virtualMachineScaleSets',
            'Microsoft.HybridCompute/Machines'
        )

        # Validate the resource type
        if ($ResourceType -in $ValidResourceTypes) {
            Write-Information -MessageData 'Validated resource type.'
        }
        else {
            Write-Error -Message "Resource: '$ResourceName' is of type: '$ResourceType' which is not supported for AMA remedation by this script."
            throw
        }

        # Validate the resource type matches what should be remediated.
        ## VM
        if (($RemediateResourceTypes -in @('All', 'VirtualMachines')) -and ($ResourceType -eq 'Microsoft.Compute/virtualMachines')) {
            Write-Information -MessageData "Matched directed remediation resource type of: '$RemediateResourceTypes' with found resource type of: '$ResourceType'"

            ### BEGIN: DISCOVERY - Resource ID - VM ###
            Write-Information -MessageData '== Starting Discovery phase for a single VM =='
            [System.String]$VMResourceGroupName = $GetAzResource.ResourceGroupName
            [System.String]$VMName = $GetAzResource.Name

            Write-Information -MessageData 'Getting VM.'
            [System.Collections.ArrayList]$AzVMArray = @()
            Get-AzVM -ResourceGroupName $VMResourceGroupName -Name $VMName | ForEach-Object -Process {
                $AzVMArray.Add($_) | Out-Null
            }
            Write-Information -MessageData '== Ending Discovery phase for a single VM =='
            ### END: DISCOVERY - Resource ID - VM ###
            ### BEGIN: ANALYSIS - Resource ID - VM ###
            Write-Information -MessageData '== Starting Analysis phase for a single VM =='
            [System.Int32]$AzVMArrayCount = $AzVMArray.Count
            if ($AzVMArrayCount -gt 0) {
                [System.Collections.ArrayList]$AzVMNoAMAArray = @()
                [System.Collections.ArrayList]$AzVMAMAHealthyArray = @()
                [System.Collections.ArrayList]$AzVMAMAUnhealthyArray = @()

                Write-Information -MessageData "Found: '$AzVMArrayCount' Azure VM in resource group: '$ResourceGroupName'."
                Write-Information -MessageData 'Enumerating VM array to find AMA extension.'

                [System.Int32]$i = 1
                [System.Int32]$TotalCount = $AzVMArray.Count
                foreach ($VM in $AzVMArray) {
                    [System.String]$VMName = $VM.Name

                    Write-Information -MessageData "Looking for AMA extension on VM: '$VMName' in resource group. Server: '$i' of: '$TotalCount'."
                    $GetAMAExtension = $VM.Extensions | Where-Object -FilterScript {
                        ($_.Name -in @('AzureMonitorWindowsAgent', 'AzureMonitorLinuxAgent')) -and ($_.Publisher -eq 'Microsoft.Azure.Monitor')
                    }

                    if ($GetAMAExtension) {
                        Write-Information -MessageData 'Found AMA extension on VM.'

                        [System.String]$AMAExtensionProvisioningState = $GetAMAExtension.ProvisioningState
                        if ($AMAExtensionProvisioningState -eq 'Succeeded') {
                            Write-Information -MessageData "Extension is in a: '$AMAExtensionProvisioningState' state."
                            $AzVMsAMAHealthyArray.Add($VM) | Out-Null
                        }
                        else {
                            Write-Information -MessageData "Extension is in a: '$AMAExtensionProvisioningState' state."
                            $AzVMsAMAUnhealthyArray.Add($VM) | Out-Null
                        }
                    }
                    else {
                        Write-Information -MessageData 'Did not find AMA extension on VM.'
                        $AzVMsNoAMAArray.Add($VM) | Out-Null
                    }

                    $i++
                }
            }
            else {
                Write-Information -MessageData 'Did not find any Azure VMs in resource group.'
            }
            Write-Information -MessageData '== Ending Analysis phase for a single VM =='
            ### END: ANALYSIS - Resource ID - VM ###
            ### BEGIN: Report - Resource ID - VM ###
            Write-Information -MessageData '== Starting Reporting phase for a single VM =='
            if ($ReportDirectoryPath -ge 3) {
                Write-Information -MessageData 'Creating current-state report names for VM.'
                [System.String]$Now = Get-Date -Format FileDateTimeUniversal
                [System.String]$AzVMNoAMAReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'VM', '_No-AMA_', $Now, '.csv')
                [System.String]$AzVMNoAMAReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzVMNoAMAReportFileName)
                [System.String]$AzVMAMAHealthyReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'VM', '_AMA-Healthy_', $Now, '.csv')
                [System.String]$AzVMAMAHealthyReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzVMAMAHealthyReportFileName)
                [System.String]$AzVMAMAUnhealthyReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'VM', '_AMA-Unhealthy_', $Now, '.csv')
                [System.String]$AzVMAMAUnhealthyReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzVMAMAUnhealthyReportFileName)

                if ($AzVMNoAMAArray.Count -ge 1) {
                    Write-Information -MessageData "Exporting report of VM without AMA to: '$AzVMsNoAMAReportFilePath'."
                    if ($PSCmdlet.ShouldProcess($AzVMNoAMAReportFilePath)) {
                        $AzVMNoAMAArray | Export-Csv -LiteralPath $AzVMNoAMAReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                    }
                    else {
                        $AzVMNoAMAArray | Export-Csv -LiteralPath $AzVMNoAMAReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                    }
                }
                else {
                    Write-Information -MessageData 'No VM without AMA to report.'
                }

                if ($AzVMAMAHealthyArray.Count -ge 1) {
                    Write-Information -MessageData "Exporting report of VM with AMA in a healthy state to: '$AzVMAMAHealthyReportFilePath'."
                    if ($PSCmdlet.ShouldProcess($AzVMAMAHealthyReportFilePath)) {
                        $AzVMAMAHealthyArray | Export-Csv -LiteralPath $AzVMAMAHealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                    }
                    else {
                        $AzVMAMAHealthyArray | Export-Csv -LiteralPath $AzVMAMAHealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                    }
                }
                else {
                    Write-Information -MessageData 'No VM with AMA in a healthy state to report.'
                }

                if ($AzVMAMAUnhealthyArray.Count -ge 1) {
                    Write-Information -MessageData "Exporting report of VM with AMA in an unhealthy state to: '$AzVMAMAUnhealthyReportFilePath'."
                    if ($PSCmdlet.ShouldProcess($AzVMAMAUnhealthyReportFilePath)) {
                        $AzVMAMAUnhealthyArray | Export-Csv -LiteralPath $AzVMAMAUnhealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                    }
                    else {
                        $AzVMAMAUnhealthyArray | Export-Csv -LiteralPath $AzVMAMAUnhealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                    }
                }
                else {
                    Write-Information -MessageData 'No VM with AMA in an unhealthy state to report.'
                }
            }
            Write-Information -MessageData '== Ending Reporting phase for a single VM =='
            ### END: Report - Resource ID - VM ###
            ### BEGIN: Remediation - Resource ID - VM ###
            Write-Information -MessageData '== Starting Remediation phase for a single VM =='
            if (!($PSBoundParameters.ContainsKey('ReportOnly'))) {
                if ($AzVMAMAUnhealthyArray.Count -ge 1) {
                    Write-Information -MessageData 'Working on removing AMA from VM with an unhealthy agent before attempting to reinstall.'

                    [System.Int32]$i = 1
                    [System.Int32]$TotalCount = $AzVMAMAUnhealthyArray.Count
                    foreach ($VM in $AzVMAMAUnhealthyArray) {
                        [System.String]$VMName = $VM.Name

                        # VM - Windows
                        if ($null -ne $VM.OSProfile.WindowsConfiguration) {
                            Write-Information -MessageData "Attempting to uninstall AMA for Windows for VM: '$VMName'. Server: '$i' of: '$TotalCount'."

                            try {
                                $ErrorActionPreference = 'Stop'
                                if ($PSCmdlet.ShouldProcess($VMName)) {
                                    Remove-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -VMName $VMName -Name AzureMonitorWindowsAgent

                                    Write-Information -MessageData "Adding VM: '$VMName' to array of VMs without AMA for reinstallation."
                                    $AzVMNoAMAArray.Add($VM) | Out-Null
                                }
                                else {
                                    Remove-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -VMName $VMName -Name AzureMonitorWindowsAgent -WhatIf
                                }
                            }
                            catch {
                                $_
                            }
                        }
                        # VM - Linux
                        elseif ($null -ne $VM.OSProfile.LinuxConfiguration) {
                            Write-Information -MessageData "Attempting to uninstall AMA for Linux for VM: '$VMName'. Server: '$i' of: '$TotalCount'."

                            try {
                                $ErrorActionPreference = 'Stop'
                                if ($PSCmdlet.ShouldProcess($VMName)) {
                                    Remove-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -VMName $VMName -Name AzureMonitorLinuxAgent

                                    Write-Information -MessageData "Adding VM: '$VMName' to array of VMs without AMA for reinstallation."
                                    $AzVMNoAMAArray.Add($VM) | Out-Null
                                }
                                else {
                                    Remove-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -VMName $VMName -Name AzureMonitorLinuxAgent -WhatIf
                                }
                            }
                            catch {
                                $_
                            }
                        }
                        else {
                            Write-Information -MessageData "The OS Profile configuration for VM: '$VMName' is unrecognized. Moving on."
                        }

                        $i++
                    }
                }
                else {
                    Write-Information -MessageData 'No VM with an unhealthy AMA to uninstall.'
                }

                if ($AzVMNoAMAArray.Count -ge 1) {
                    Write-Information -MessageData 'Working on remediating VM without AMA or those which had an unhealthy AMA.'

                    [System.Int32]$i = 1
                    [System.Int32]$TotalCount = $AzVMNoAMAArray.Count
                    foreach ($VM in $AzVMNoAMAArray) {
                        [System.String]$VMName = $VM.Name
                        ## VM - Windows
                        if ($null -ne $VM.OSProfile.WindowsConfiguration) {
                            Write-Information -MessageData "Attempting to add AMA for Windows for VM: '$VMName'. Server: '$i' of: '$TotalCount'."
                            try {
                                $ErrorActionPreference = 'Stop'

                                if ($PSBoundParameters.ContainsKey('ProxyURLAndPort') -and $PSBoundParameters.ContainsKey('ProxyCredential')) {
                                    Write-Information -MessageData '... using an authenticated proxy.'
                                    if ($PSCmdlet.ShouldProcess($VMName)) {
                                        $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorWindowsAgent' -SettingString $AMASettingsStringWindowsAndLinux -ProtectedSettingString $AMAProtectedSettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                    }
                                    else {
                                        $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorWindowsAgent' -SettingString $AMASettingsStringWindowsAndLinux -ProtectedSettingString $AMAProtectedSettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                    }
                                }
                                elseif ($PSBoundParameters.ContainsKey('ProxyURLAndPort')) {
                                    Write-Information -MessageData '... using an unauthenticated proxy.'

                                    if ($PSCmdlet.ShouldProcess($VMName)) {
                                        $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorWindowsAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                    }
                                    else {
                                        $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorWindowsAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                    }
                                }
                                else {
                                    Write-Information -MessageData '... without a proxy.'

                                    if ($PSCmdlet.ShouldProcess($VMName)) {
                                        $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorWindowsAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                    }
                                    else {
                                        $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorWindowsAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                    }
                                }
                            }
                            catch {
                                $_
                            }
                        }
                        ## VM - Linux
                        elseif ($null -ne $VM.OSProfile.LinuxConfiguration) {
                            Write-Information -MessageData "Attempting to add AMA for Linux for VM: '$VMName'. Server: '$i' of: '$TotalCount'."
                            try {
                                $ErrorActionPreference = 'Stop'

                                if ($PSBoundParameters.ContainsKey('ProxyURLAndPort') -and $PSBoundParameters.ContainsKey('ProxyCredential')) {
                                    Write-Information -MessageData '... using an authenticated proxy.'
                                    if ($PSCmdlet.ShouldProcess($VMName)) {
                                        $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorLinuxAgent' -SettingString $AMASettingsStringWindowsAndLinux -ProtectedSettingString $AMAProtectedSettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                    }
                                    else {
                                        $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorLinuxAgent' -SettingString $AMASettingsStringWindowsAndLinux -ProtectedSettingString $AMAProtectedSettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                    }
                                }
                                elseif ($PSBoundParameters.ContainsKey('ProxyURLAndPort')) {
                                    Write-Information -MessageData '... using an unauthenticated proxy.'

                                    if ($PSCmdlet.ShouldProcess($VMName)) {
                                        $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorLinuxAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                    }
                                    else {
                                        $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorLinuxAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                    }
                                }
                                else {
                                    Write-Information -MessageData '... without a proxy.'

                                    if ($PSCmdlet.ShouldProcess($VMName)) {
                                        $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorLinuxAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                    }
                                    else {
                                        $VM | Set-AzVMExtension -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -ExtensionName 'AzureMonitorLinuxAgent' -SettingString $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                    }
                                }
                            }
                            catch {
                                $_
                            }
                        }
                        ## VM - Undetermined
                        else {
                            Write-Information -MessageData "The VM OS Profile configuration for VM: '$VMName' is unrecognized. Moving on."
                        }

                        $i++
                    }
                }
                else {
                    Write-Information -MessageData 'No VM missing AMA to remediate.'
                }
            }
            ### END: Remediation - Resource ID - VM ###
        }
        ## VMSS
        elseif (($RemediateResourceTypes -in @('All', 'VirtualMachineScaleSets')) -and ($ResourceType -eq 'Microsoft.Compute/virtualMachineScaleSets')) {
            Write-Information -MessageData "Matched directed remediation resource type of: '$RemediateResourceTypes' with found resource type of: '$ResourceType'"

            ### BEGIN: DISCOVERY - Resource ID - VMSS ###
            Write-Information -MessageData '== Starting Discovery phase for a single VM Scale Set =='
            [System.String]$VMSSResourceGroupName = $GetAzResource.ResourceGroupName
            [System.String]$VMSSName = $GetAzResource.Name

            Write-Information -MessageData 'Getting VM Scale Set.'
            [System.Collections.ArrayList]$AzVMSSArray = @()
            Get-AzVmss -ResourceGroupName $VMSSResourceGroupName -Name $VMSSName | ForEach-Object -Process {
                $AzVMSSArray.Add($_) | Out-Null
            }
            Write-Information -MessageData '== Ending Discovery phase for a single VM Scale Set =='
            ### END: DISCOVERY - Resource ID - VMSS ###
            ### BEGIN: ANALYSIS - Resource ID - VMSS ###
            Write-Information -MessageData '== Starting Analysis phase for a single VM Scale Set =='
            [System.Int32]$AzVMSSArrayCount = $AzVMSSArray.Count
            if ($AzVMSSArrayCount -gt 0) {
                [System.Collections.ArrayList]$AzVMSSNoAMAArray = @()
                [System.Collections.ArrayList]$AzVMSSAMAHealthyArray = @()
                [System.Collections.ArrayList]$AzVMSSAMAUnhealthyArray = @()

                Write-Information -MessageData "Found: '$AzVMSSArrayCount' Azure VM Scale Sets in resource group: '$ResourceGroupName'."
                Write-Information -MessageData 'Enumerating VM Scale Set array to find AMA extension.'

                [System.Int32]$i = 1
                [System.Int32]$TotalCount = $AzVMSSArray.Count
                foreach ($VMSS in $AzVMSSArray) {
                    [System.String]$VMSSName = $VMSS.Name

                    Write-Information -MessageData "Looking for AMA extension on VM Scale Set: '$VMSSName' in resource group. Server: '$i' of: '$TotalCount'."
                    $GetAMAExtension = $VMSS.VirtualMachineProfile.ExtensionProfile.Extensions | Where-Object -FilterScript {
                        ($_.Name -in @('AzureMonitorWindowsAgent', 'AzureMonitorLinuxAgent')) -and ($_.Publisher -eq 'Microsoft.Azure.Monitor')
                    }

                    if ($GetAMAExtension) {
                        Write-Information -MessageData 'Found AMA extension on VM Scale Set.'

                        [System.String]$AMAExtensionProvisioningState = $GetAMAExtension.ProvisioningState
                        if ($AMAExtensionProvisioningState -eq 'Succeeded') {
                            Write-Information -MessageData "Extension is in a: '$AMAExtensionProvisioningState' state."
                            $AzVMSSAMAHealthyArray.Add($VMSS) | Out-Null
                        }
                        else {
                            Write-Information -MessageData "Extension is in a: '$AMAExtensionProvisioningState' state."
                            $AzVMSSAMAUnhealthyArray.Add($VMSS) | Out-Null
                        }
                    }
                    else {
                        Write-Information -MessageData 'Did not find AMA extension on VM Scale Set.'
                        $AzVMSSNoAMAArray.Add($VMSS) | Out-Null
                    }

                    $i++
                }
            }
            else {
                Write-Information -MessageData 'Did not find any Azure VM Scale Sets in resource group.'
            }
            Write-Information -MessageData '== Ending Analysis phase for a single VM Scale Set =='
            ### END: ANALYSIS - Resource ID - VMSS ###
            ### BEGIN: Report - Resource ID - VMSS ###
            Write-Information -MessageData '== Starting Reporting phase for a single VM Scale Set =='
            if ($ReportDirectoryPath -ge 3) {
                Write-Information -MessageData 'Creating current-state report names for VM.'
                [System.String]$Now = Get-Date -Format FileDateTimeUniversal
                [System.String]$AzVMSSNoAMAReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'VMSS', '_No-AMA_', $Now, '.csv')
                [System.String]$AzVMSSNoAMAReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzVMSSNoAMAReportFileName)
                [System.String]$AzVMSSAMAHealthyReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'VMSS', '_AMA-Healthy_', $Now, '.csv')
                [System.String]$AzVMSSAMAHealthyReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzVMSSAMAHealthyReportFileName)
                [System.String]$AzVMSSAMAUnhealthyReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'VMSS', '_AMA-Unhealthy_', $Now, '.csv')
                [System.String]$AzVMSSAMAUnhealthyReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzVMSSAMAUnhealthyReportFileName)

                if ($AzVMNoAMAArray.Count -ge 1) {
                    Write-Information -MessageData "Exporting report of VM Scale Set without AMA to: '$AzVMSSNoAMAReportFilePath'."
                    if ($PSCmdlet.ShouldProcess($AzVMSSNoAMAReportFilePath)) {
                        $AzVMSSNoAMAArray | Export-Csv -LiteralPath $AzVMSSNoAMAReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                    }
                    else {
                        $AzVMSSNoAMAArray | Export-Csv -LiteralPath $AzVMSSNoAMAReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                    }
                }
                else {
                    Write-Information -MessageData 'No VM Scale Set without AMA to report.'
                }

                if ($AzVMSSAMAHealthyArray.Count -ge 1) {
                    Write-Information -MessageData "Exporting report of VM Scale Set with AMA in a healthy state to: '$AzVMSSAMAHealthyReportFilePath'."
                    if ($PSCmdlet.ShouldProcess($AzVMSSAMAHealthyReportFilePath)) {
                        $AzVMSSAMAHealthyArray | Export-Csv -LiteralPath $AzVMSSAMAHealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                    }
                    else {
                        $AzVMSSAMAHealthyArray | Export-Csv -LiteralPath $AzVMSSAMAHealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                    }
                }
                else {
                    Write-Information -MessageData 'No VM Scale Set with AMA in a healthy state to report.'
                }

                if ($AzVMSSAMAUnhealthyArray.Count -ge 1) {
                    Write-Information -MessageData "Exporting report of VM Scale Set with AMA in an unhealthy state to: '$AzVMSSAMAUnhealthyReportFilePath'."
                    if ($PSCmdlet.ShouldProcess($AzVMSSAMAUnhealthyReportFilePath)) {
                        $AzVMSSAMAUnhealthyArray | Export-Csv -LiteralPath $AzVMSSAMAUnhealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                    }
                    else {
                        $AzVMSSAMAUnhealthyArray | Export-Csv -LiteralPath $AzVMSSAMAUnhealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                    }
                }
                else {
                    Write-Information -MessageData 'No VM Scale Set with AMA in an unhealthy state to report.'
                }
            }
            Write-Information -MessageData '== Ending Reporting phase for a single VM Scale Set =='
            ### END: Report - Resource ID - VMSS ###
            ### BEGIN: Remediation - Resource ID - VMSS ###
            Write-Information -MessageData '== Starting Remediation phase for a single VM Scale Set =='
            if (!($PSBoundParameters.ContainsKey('ReportOnly'))) {
                if ($AzVMSSNoAMAArray.Count -ge 1) {
                    Write-Information -MessageData 'Working on remediating VM Scale Set without AMA or those which had an unhealthy AMA.'

                    [System.Int32]$i = 1
                    [System.Int32]$TotalCount = $AzVMSSNoAMAArray.Count
                    foreach ($VMSS in $AzVMSSNoAMAArray) {
                        [System.String]$VMSSName = $VMSS.Name
                        ## VMSS - Windows
                        if ($null -ne $VMSS.OSProfile.WindowsConfiguration) {
                            Write-Information -MessageData "Attempting to add AMA for Windows for VM Scale Set: '$VMSSName'. Server: '$i' of: '$TotalCount'."
                            try {
                                $ErrorActionPreference = 'Stop'

                                if ($PSBoundParameters.ContainsKey('ProxyURLAndPort') -and $PSBoundParameters.ContainsKey('ProxyCredential')) {
                                    Write-Information -MessageData '... using an authenticated proxy.'
                                    if ($PSCmdlet.ShouldProcess($VMName)) {
                                        Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringWindowsAndLinux -ProtectedSetting $AMAProtectedSettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                    }
                                    else {
                                        Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringWindowsAndLinux -ProtectedSetting $AMAProtectedSettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                    }
                                }
                                elseif ($PSBoundParameters.ContainsKey('ProxyURLAndPort')) {
                                    Write-Information -MessageData '... using an unauthenticated proxy.'

                                    if ($PSCmdlet.ShouldProcess($VMName)) {
                                        Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                    }
                                    else {
                                        Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                    }
                                }
                                else {
                                    Write-Information -MessageData '... without a proxy.'

                                    if ($PSCmdlet.ShouldProcess($VMName)) {
                                        Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                    }
                                    else {
                                        Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                    }
                                }
                            }
                            catch {
                                $_
                            }
                        }
                        ## VMSS - Linux
                        elseif ($null -ne $VMSS.OSProfile.LinuxConfiguration) {
                            Write-Information -MessageData "Attempting to add AMA for Linux for VM Scale Set: '$VMSSName'. Server: '$i' of: '$TotalCount'."
                            try {
                                $ErrorActionPreference = 'Stop'

                                if ($PSBoundParameters.ContainsKey('ProxyURLAndPort') -and $PSBoundParameters.ContainsKey('ProxyCredential')) {
                                    Write-Information -MessageData '... using an authenticated proxy.'
                                    if ($PSCmdlet.ShouldProcess($VMSSName)) {
                                        Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -ProtectedSetting $AMAProtectedSettingsStringWindowsAndLinux
                                    }
                                    else {
                                        Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -ProtectedSetting $AMAProtectedSettingsStringWindowsAndLinux -WhatIf
                                    }
                                }
                                elseif ($PSBoundParameters.ContainsKey('ProxyURLAndPort')) {
                                    Write-Information -MessageData '... using an unauthenticated proxy.'

                                    if ($PSCmdlet.ShouldProcess($VMSSName)) {
                                        Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                    }
                                    else {
                                        Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                    }
                                }
                                else {
                                    Write-Information -MessageData '... without a proxy.'

                                    if ($PSCmdlet.ShouldProcess($VMSSName)) {
                                        Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true
                                    }
                                    else {
                                        Add-AzVmssExtension -VirtualMachineScaleSet $VMSS -Type 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringWindowsAndLinux -EnableAutomaticUpgrade $true -WhatIf
                                    }
                                }
                            }
                            catch {
                                $_
                            }
                        }
                        ## VMSS - Undetermined
                        else {
                            Write-Information -MessageData "The OS Profile configuration for VM Scale Set: '$VMSSName' is unrecognized. Moving on."
                        }

                        $i++
                    }
                }
                else {
                    Write-Information -MessageData 'No VM Scale Sets missing AMA to remediate.'
                }
            }
            ### END: Remediation - Resource ID - VMSS ###
        }
        ## Arc
        elseif (($RemediateResourceTypes -in @('All', 'ArcEnabledServers')) -and ($ResourceType -eq 'Microsoft.HybridCompute/machines')) {
            Write-Information -MessageData "Matched directed remediation resource type of: '$RemediateResourceTypes' with found resource type of: '$ResourceType'"

            ### BEGIN: DISCOVERY - Resource ID - Arc ###
            Write-Information -MessageData '== Starting Discovery phase for an Arc-enabled Server =='
            [System.String]$ConnectedMachineResourceGroupName = [System.Convert]::ToString($GetAzResource.ResourceGroupName)
            [System.String]$ConnectedMachineName = [System.Convert]::ToString($GetAzResource.Name)

            Write-Information -MessageData 'Getting Arc-enabled Server.'
            [System.Collections.ArrayList]$AzConnectedMachineArray = @()
            Get-AzConnectedMachine -ResourceGroupName $ConnectedMachineResourceGroupName -Name $ConnectedMachineName | ForEach-Object -Process {
                $AzConnectedMachineArray.Add($_) | Out-Null
            }
            Write-Information -MessageData '== Ending Discovery phase for an Arc-enabled Server =='
            ### END: DISCOVERY - Resource ID - Arc ###
            ### BEGIN: ANALYSIS - Resource ID - Arc ###
            Write-Information -MessageData '== Starting Analysis phase for a single Arc-enabled Server =='
            [System.Int32]$AzConnectedMachineArrayCount = $AzConnectedMachineArray.Count
            if ($AzConnectedMachineArrayCount -gt 0) {
                [System.Collections.ArrayList]$AzConnectedMachineNoAMAArray = @()
                [System.Collections.ArrayList]$AzConnectedMachineAMAHealthyArray = @()
                [System.Collections.ArrayList]$AzConnectedMachineAMAUnhealthyArray = @()
                [System.Collections.ArrayList]$AzConnectedMachineNotConnectedArray = @()

                Write-Information -MessageData "Found: '$AzConnectedMachineArrayCount' Azure Arc-enabled Servers in resource group: '$ResourceGroupName'."
                Write-Information -MessageData 'Enumerating Arc-enabled Server array to find AMA extension.'

                [System.Int32]$i = 1
                [System.Int32]$TotalCount = $AzConnectedMachineArray.Count
                foreach ($ConnectedMachine in $AzConnectedMachineArray) {
                    [System.String]$ConnectedMachineName = $ConnectedMachine.Name

                    Write-Information -MessageData "Looking for AMA extension on Arc-enabled Server: '$ConnectedMachineName' in resource group. Server: '$i' of: '$TotalCount'."
                    $GetAMAExtension = $ConnectedMachine.VirtualMachineProfile.ExtensionProfile.Extensions | Where-Object -FilterScript {
                        ($_.Name -in @('AzureMonitorWindowsAgent', 'AzureMonitorLinuxAgent')) -and ($_.Publisher -eq 'Microsoft.Azure.Monitor')
                    }

                    if ('Connected' -eq $ConnectedMachine.Status) {
                        Write-Information -MessageData 'Arc-enabled Server is connected.'
                        if ($GetAMAExtension) {
                            Write-Information -MessageData 'Found AMA extension on Arc-enabled Server.'

                            [System.String]$AMAExtensionProvisioningState = $GetAMAExtension.ProvisioningState
                            if ($AMAExtensionProvisioningState -eq 'Succeeded') {
                                Write-Information -MessageData "Extension is in a: '$AMAExtensionProvisioningState' state."
                                $AzConnectedMachineAMAHealthyArray.Add($ConnectedMachine) | Out-Null
                            }
                            else {
                                Write-Information -MessageData "Extension is in a: '$AMAExtensionProvisioningState' state."
                                $AzConnectedMachineAMAUnhealthyArray.Add($ConnectedMachine) | Out-Null
                            }
                        }
                        else {
                            Write-Information -MessageData 'Did not find AMA extension on Arc-enabled Server.'
                            $AzConnectedMachineNoAMAArray.Add($ConnectedMachine) | Out-Null
                        }
                    }
                    else {
                        Write-Warning -Message "Arc-enabled Server: '$ConnectedMachineName' is not connected."
                        $AzConnectedMachinesNotConnectedArray.Add($ConnectedMachine) | Out-Null
                    }

                    $i++
                }
            }
            else {
                Write-Information -MessageData 'Did not find any Azure Arc-enabled Servers in resource group.'
            }
            Write-Information -MessageData '== Ending Analysis phase for a single Arc-enabled Server =='
            ### END: ANALYSIS - Resource ID - Arc ###
            ### BEGIN: Report - Resource ID - Arc ###
            Write-Information -MessageData '== Starting Reporting phase for a single Arc-enabled Server =='
            if ($ReportDirectoryPath -ge 3) {
                Write-Information -MessageData 'Creating current-state report names for VM.'
                [System.String]$Now = Get-Date -Format FileDateTimeUniversal
                [System.String]$AzConnectedMachineNoAMAReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'Arc', '_No-AMA_', $Now, '.csv')
                [System.String]$AzConnectedMachineNoAMAReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzConnectedMachineNoAMAReportFileName)
                [System.String]$AzConnectedMachineAMAHealthyReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'Arc', '_AMA-Healthy_', $Now, '.csv')
                [System.String]$AzConnectedMachineAMAHealthyReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzConnectedMachineAMAHealthyReportFileName)
                [System.String]$AzConnectedMachineAMAUnhealthyReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'Arc', '_AMA-Unhealthy_', $Now, '.csv')
                [System.String]$AzConnectedMachineAMAUnhealthyReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzConnectedMachineAMAUnhealthyReportFileName)
                [System.String]$AzConnectedMachineNotConnectedReportFileName = [System.String]::Concat($ScriptNameNoExt, '_', 'Arc', '_Not-Connected_', $Now, '.csv')
                [System.String]$AzConnectedMachineNotConnectedReportFilePath = [System.String]::Concat($ReportDirectoryPathNormalized, '\', $AzConnectedMachineNotConnectedReportFileName)

                if ($AzConnectedMachineNoAMAArray.Count -ge 1) {
                    Write-Information -MessageData "Exporting report of Arc-enabled Server without AMA to: '$AzConnectedMachineNoAMAReportFilePath'."
                    if ($PSCmdlet.ShouldProcess($AzConnectedMachineNoAMAReportFilePath)) {
                        $AzConnectedMachineNoAMAArray | Export-Csv -LiteralPath $AzConnectedMachineNoAMAReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                    }
                    else {
                        $AzConnectedMachineNoAMAArray | Export-Csv -LiteralPath $AzConnectedMachineNoAMAReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                    }
                }
                else {
                    Write-Information -MessageData 'No Arc-enabled Server without AMA to report.'
                }

                if ($AzConnectedMachineAMAHealthyArray.Count -ge 1) {
                    Write-Information -MessageData "Exporting report of Arc-enabled Server with AMA in a healthy state to: '$AzConnectedMachineAMAHealthyReportFilePath'."
                    if ($PSCmdlet.ShouldProcess($AzConnectedMachineAMAHealthyReportFilePath)) {
                        $AzConnectedMachineAMAHealthyArray | Export-Csv -LiteralPath $AzConnectedMachineAMAHealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                    }
                    else {
                        $AzConnectedMachineAMAHealthyArray | Export-Csv -LiteralPath $AzConnectedMachineAMAHealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                    }
                }
                else {
                    Write-Information -MessageData 'No Arc-enabled Server with AMA in a healthy state to report.'
                }

                if ($AzConnectedMachineAMAUnhealthyArray.Count -ge 1) {
                    Write-Information -MessageData "Exporting report of Arc-enabled Server with AMA in an unhealthy state to: '$AzConnectedMachineAMAUnhealthyReportFilePath'."
                    if ($PSCmdlet.ShouldProcess($AzConnectedMachineAMAUnhealthyReportFilePath)) {
                        $AzConnectedMachineAMAUnhealthyArray | Export-Csv -LiteralPath $AzConnectedMachineAMAUnhealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                    }
                    else {
                        $AzConnectedMachineAMAUnhealthyArray | Export-Csv -LiteralPath $AzConnectedMachineAMAUnhealthyReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                    }
                }
                else {
                    Write-Information -MessageData 'No Arc-enabled Server which is not connected to report.'
                }

                if ($AzConnectedMachineNotConnectedArray.Count -ge 1) {
                    Write-Information -MessageData "Exporting report of Arc-enabled Server which is not connected to: '$AzConnectedMachineNotConnectedReportFilePath'."
                    if ($PSCmdlet.ShouldProcess($AzConnectedMachineNotConnectedReportFilePath)) {
                        $AzConnectedMachineNotConnectedArray | Export-Csv -LiteralPath $AzConnectedMachineNotConnectedReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation
                    }
                    else {
                        $AzConnectedMachineNotConnectedArray | Export-Csv -LiteralPath $AzConnectedMachineNotConnectedReportFilePath -Encoding utf8 -Delimiter ',' -NoClobber -IncludeTypeInformation -WhatIf
                    }
                }
                else {
                    Write-Information -MessageData 'No Arc-enabled Server which is not connected to report.'
                }
            }
            Write-Information -MessageData '== Ending Reporting phase for a single Arc-enabled Server =='
            ### END: Report - Resource ID - Arc ###
            ### BEGIN: Remediation - Resource ID - Arc ###
            Write-Information -MessageData '== Starting Remediation phase for a single Arc-enabled Server =='
            if (!($PSBoundParameters.ContainsKey('ReportOnly'))) {
                if ($AzConnectedMachineNoAMAArray.Count -ge 1) {
                    Write-Information -MessageData 'Working on remediating Arc-enabled Servers without AMA or those which had an unhealthy AMA.'

                    [System.Int32]$i = 1
                    [System.Int32]$TotalCount = $AzConnectedMachineNoAMAArray.Count
                    foreach ($ConnectedMachine in $AzConnectedMachineNoAMAArray) {
                        [System.String]$ConnectedMachineName = $ConnectedMachine.Name
                        ## Arc - Windows
                        if ('windows' -eq $ConnectedMachine.OSType) {
                            Write-Information -MessageData "Attempting to add AMA for Windows for Arc-enabled Server: '$ConnectedMachineName'. Server: '$i' of: '$TotalCount'."
                            try {
                                $ErrorActionPreference = 'Stop'

                                if ($PSBoundParameters.ContainsKey('ProxyURLAndPort') -and $PSBoundParameters.ContainsKey('ProxyCredential')) {
                                    Write-Information -MessageData '... using an authenticated proxy.'
                                    if ($PSCmdlet.ShouldProcess($ConnectedMachineName)) {
                                        New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringArc -ProtectedSetting $AMAProtectedSettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade
                                    }
                                    else {
                                        New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringArc -ProtectedSetting $AMAProtectedSettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade -WhatIf
                                    }
                                }
                                elseif ($PSBoundParameters.ContainsKey('ProxyURLAndPort')) {
                                    Write-Information -MessageData '... using an unauthenticated proxy.'

                                    if ($PSCmdlet.ShouldProcess($ConnectedMachineName)) {
                                        New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade
                                    }
                                    else {
                                        New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade -WhatIf
                                    }
                                }
                                else {
                                    Write-Information -MessageData '... without a proxy.'

                                    if ($PSCmdlet.ShouldProcess($ConnectedMachineName)) {
                                        New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade
                                    }
                                    else {
                                        New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorWindowsAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorWindowsAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade -WhatIf
                                    }
                                }
                            }
                            catch {
                                $_
                            }
                        }
                        ## Arc - Linux
                        elseif ('linux' -eq $ConnectedMachine.OSType) {
                            Write-Information -MessageData "Attempting to add AMA for Linux for Arc-enabled Server: '$ConnectedMachineName'. Server: '$i' of: '$TotalCount'."
                            try {
                                $ErrorActionPreference = 'Stop'

                                if ($PSBoundParameters.ContainsKey('ProxyURLAndPort') -and $PSBoundParameters.ContainsKey('ProxyCredential')) {
                                    Write-Information -MessageData '... using an authenticated proxy.'
                                    if ($PSCmdlet.ShouldProcess($ConnectedMachineName)) {
                                        New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringArc -ProtectedSetting $AMAProtectedSettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade
                                    }
                                    else {
                                        New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringArc -ProtectedSetting $AMAProtectedSettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade -WhatIf
                                    }
                                }
                                elseif ($PSBoundParameters.ContainsKey('ProxyURLAndPort')) {
                                    Write-Information -MessageData '... using an unauthenticated proxy.'

                                    if ($PSCmdlet.ShouldProcess($ConnectedMachineName)) {
                                        New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade
                                    }
                                    else {
                                        New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade -WhatIf
                                    }
                                }
                                else {
                                    Write-Information -MessageData '... without a proxy.'

                                    if ($PSCmdlet.ShouldProcess($ConnectedMachineName)) {
                                        New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade
                                    }
                                    else {
                                        New-AzConnectedMachineExtension -ResourceGroupName $ConnectedMachine.ResourceGroupName -MachineName $ConnectedMachineName -Location $ConnectedMachine.location -ExtensionType 'AzureMonitorLinuxAgent' -Publisher 'Microsoft.Azure.Monitor' -Name 'AzureMonitorLinuxAgent' -Setting $AMASettingsStringArc -AutoUpgradeMinorVersion -EnableAutomaticUpgrade -WhatIf
                                    }
                                }
                            }
                            catch {
                                $_
                            }
                        }
                        ## Arc - Undetermined
                        else {
                            Write-Information -MessageData "The OS Profile configuration for Arc-enabled Server: '$ConnectedMachineName' is unrecognized. Moving on."
                        }

                        $i++
                    }
                }
                else {
                    Write-Information -MessageData 'No Arc-enabled Servers missing AMA to remediate.'
                }
            }
            ### END: Remediation - Resource ID - Arc ###
        }
        ## Unknown
        else {
            Write-Error -Message "Directed remediation resource type is: '$RemediateResourceTypes', but found resource type was: '$ResourceType'. Please re-run again supplying a valid combination."
        }
    }
    else {
        Write-Error -Message 'An invalid Resource ID length was specified. Please try again.'
    }
}
### END: Resource ID ###
### BEGIN: Unknown Parameter Combination ###
else {
    Write-Error -Message 'Neither a Resource Group Name nor a Resource ID were supplied. Please re-run specifying one of those parameters and accompanying parameter values.'
    throw
}
### END: Unknown Parameter Combination ###
Write-Information -MessageData 'Exiting.'