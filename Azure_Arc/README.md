---
services: Azure Arc
platforms: Azure
author: scottmetzel
date: 01/08/2025
---
Tools in this directory are used with Azure Arc. Please refer to the list below to read more about each one.

# Tools for Azure Arc
1. [Enable Windows Server Management via Azure Arc](#enable-windows-server-management-via-azure-arc)


<a name="EnableWinSrvManagement"></a>
## Enable Windows Server Management via Azure Arc
This tool provides a scalable solution for enrolling in [Windows Server Management by Azure Arc](https://learn.microsoft.com/en-us/azure/azure-arc/servers/windows-server-management-overview?tabs=portal). The easiest way to execute it is to download it, then upload to and execute via [Azure Cloud Shell](https://learn.microsoft.com/en-us/azure/cloud-shell/overview). Don't have a Cloud Shell? [Read this to get started!](https://learn.microsoft.com/en-us/azure/cloud-shell/get-started/ephemeral?tabs=azurecli)

It can enroll Arc-enabled Servers in Windows Server Management at all scopes, which means it can enroll all discovered Arc-enabled Servers:
 - using no filtering, which can span tenants.
 - those which are associated with specific Entra ID tenants by specifying the tenant IDs.
 - those reside under specific Azure Management Groups, using Management Group IDs.
 - those which are in specific Azure Subscriptions, using Subscription IDs.
 - all Arc-enabled Servers in resource groups, using resource group names.
 - specific Arc-enabled Servers using their names, across resource groups.
 - or specific ones using their names within the same resource group.

Despite all this fanciness, it doesn't take much to run.

### Prerequisites
- Your Work or School Account must be assigned the [*Azure Connected Machine Resource Administrator*](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/management-and-governance#azure-connected-machine-resource-administrator) role.
- You must be connected to Azure.
  - Azure Cloud Shell automatically signs you in!
  - (Optional) - If your account has access to multiple Entra ID tenants and Azure subscriptions, make sure to log in using a specific tenant ID or execute the script to run in the desired context. Please see the execution examples below.
- PowerShell 7 is required.
  - Azure Cloud Shell already runs this!
- The 'Az.Accounts' and 'Az.Resources' PowerShell modules must be installed.
  - Azure Cloud Shell already has these modules installed, and it keeps them up to date!

### How to execute
I recommend downloading this script, and then uploading it to a CloudShell session. Once uploaded, the script can be executed using the examples below, which assume you're not connected to Azure (again, CloudShell automatically connects your account to Azure).

This will work in a local PowerShell 7 session as well, but CloudShell offloads maintenance of modules and has connectivity to Azure, too.

### Examples
#### Example 1 - Unfiltered
```
PS> Connect-AzAccount
PS> .\Enable-WindowsServerManagementByAzureArc.ps1
```
Running the tool this way will attempt to enroll all servers it discovers at all scopes and can span Entra ID tenants, if your account has the requisite role across tenants. It's the simplest way to enroll your servers.

#### Example 2 - Unfiltered with Reporting
```
PS> Connect-AzAccount
PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ReportDirectoryPath 'C:\Temp'
```
Running the tool this way will attempt to enroll all servers it discovers at all scopes and can span Entra ID tenants, if your account has the requisite role across tenants. This also creates a report within an existing directory named 'C:\Temp'. The report name contains the name of the script and the date & time it was executed, in CSV format. Reports do not overwrite files with the same name.

#### Example 3 - Unfiltered with Reporting Only
```
PS> Connect-AzAccount
PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ReportDirectoryPath 'C:\Temp' -ReportOnly
```
Running the tool this way only reports on all servers it discovers at all scopes and can span Entra ID tenants, if your account has the requisite role across tenants. This also creates a report within an existing directory named 'C:\Temp'. The report name contains the name of the script and the date & time it was executed, in CSV format. This is different than adding 'WhatIf', in that a report will be written to disk; when running this with 'WhatIf' no report is generated (hey it's 'WhatIf'.)

#### Example 4 - Filtering by Tenant ID
```
PS> Connect-AzAccount -TenantID '00000000-0000-0000-0000-000000000000'
PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -WhatIf
```
Running the tool this way would attempt to enroll all servers it discovers at all scopes associated with a specific Entra ID tenant ID. Specifying 'WhatIf' gives insight as to what could be changed, but does not enroll.

#### Example 5 - Filtering with Multiple Tenant IDs
```
PS> [System.String]$TenantID1 = '00000000-0000-0000-0000-000000000000'
PS> [System.String]$TenantID2 = '11111111-1111-1111-1111-111111111111'
PS> Connect-AzAccount -TenantID $TenantID1
PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -TenantIDs $TenantID1, $TenantID2
```
Running the tool this way will attempt to enroll all servers it discovers at all scopes associated with specific Entra ID tenant IDs. There's no 'WhatIf' specified here so it'll attempt to enroll whatever it discovers.

#### Example 6 - Filtering by Management Group ID
```
PS> Connect-AzAccount -ManagementGroupIDs 'MyOrg_Production'
PS> .\Enable-WindowsServerManagementByAzureArc.ps1
```
Running the tool this way will attempt to enroll all servers it discovers which reside under a specific Management Group, using its ID.

#### Example 7 - Filtering with multiple Management Group IDs
```
PS> Connect-AzAccount -ManagementGroupIDs 'MyOrg_Development','MyOrg_Production'
PS> .\Enable-WindowsServerManagementByAzureArc.ps1
```
Running the tool this way will attempt to enroll all servers it discovers which reside under specific Management Groups, using their IDs.

#### Example 8 - Filtering by Azure Subscription ID
```
PS> Connect-AzAccount
PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -SubscriptionIDs '00000000-0000-0000-0000-000000000000'
```
Running the tool this way will attempt to enroll all servers it discovers which reside in a specific Azure Subscription, using its ID.

#### Example 9 - Filtering by Azure Subscription ID
```
PS> Connect-AzAccount
PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -SubscriptionIDs '00000000-0000-0000-0000-000000000000', '11111111-1111-1111-1111-111111111111'
```
Running the tool this way will attempt to enroll all servers it discovers which reside in specific Azure Subscriptions, using their IDs.

#### Example 10 - Filtering by Resource Group
```
PS> Connect-AzAccount
PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01'
```
Running the tool this way will attempt to enroll all servers it discovers which reside in a specific resource group.

#### Example 11 - Filtering by Resource Group
```
# Multiple resource groups
PS> Connect-AzAccount
PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01', 'Prod-RG-Arc-02'
```
Running the tool this way will attempt to enroll all servers it discovers which reside in specific resource groups.

#### Example 12 - Filtering by Resource Groups and Server Names
```
# Multiple resource groups
PS> Connect-AzAccount
PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01', 'Prod-RG-Arc-02' -MachineNames 'Server1'
```
Running the tool this way will attempt to enroll specific servers it discovers which reside in specific resource groups. If an Arc-enabled Server named 'Server1' resides in both resource groups, both servers will attempt to be enrolled. If it only resides in one resource group, but not the other, only one server will be enrolled.

#### Example 13 - Filtering by Resource Groups and Server Names
```
# Multiple resource groups
PS> Connect-AzAccount
PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01', 'Prod-RG-Arc-02' -MachineNames 'Server1', 'Server2'
```
Running the tool this way will attempt to enroll specific servers it discovers which reside in specific resource groups. Like the previous example, if there are multiple matches for the server names across resource groups, an attempt will be made at enrolling them.

#### Example 14 - Filtering by Resource Groups and Server Names
```
# Multiple resource groups
PS> Connect-AzAccount
PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01', 'Prod-RG-Arc-02' -MachineNames 'Server1', 'Server2'
```
Running the tool this way will attempt to enroll specific servers it discovers which reside in specific resource groups. Like the previous example, if there are multiple matches for the server names across resource groups, an attempt will be made at enrolling them.

#### Example 15 - Filtering by Resource Group and Server Names
```
# Multiple resource groups
PS> Connect-AzAccount
PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01' -MachineNames 'Server1', 'Server2'
```
Running the tool this way will attempt to enroll specific servers it discovers which reside in a resource group.

#### Example 16 - Filtering by Server Names
```
PS> Connect-AzAccount
PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -MachineNames 'Server1', 'Server2'
```
Running the tool this way will attempt to enroll specific servers it discovers which may reside in the same or different resource groups within the same subscription. Enrolling servers using specific resource group or server names always occur in the current subscription context.

#### Example 17 - Excluding a Server
```
PS> Connect-AzAccount
PS> Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
PS> .\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01' '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Prod-RG-Arc-01/providers/Microsoft.HybridCompute/machines/Server3'
```
Running the tool this way will attempt to enroll all servers it discovers in a specific resource group, but excludes a server using its Resource ID.