---
services: Azure Arc
platforms: Azure
author: scottmetzel
date: 01/08/2025
---
# Overview

This script provides a scaleable solution for enabling Windows Server Management by Azure Arc on a Subscription, Resource Group, or Individual Arc-enabled Server.

# Prerequisites

- You must be assigned the *Azure Connected Machine Resource Administrator* role for the scope the script is run at.
- You must be connected to Azure. If your account have access to multiple Entra ID tenants and Azure subscriptions, make sure to log in with a specific tenant ID.


# Launching the script

To use this script, simply download the repository and navigate to the downloaded directory in Powershell.

Usage requires connecting to Azure via `Connect-AzAccount` with a user with the
 `Azure Connected Machine Resource Administrator` role. If you have multiple Entra ID tenants
 and subscriptions, ensure you log in with a specific Tenant ID via `Connect-AzAccount 

You will additionally need to run `Connect-AzAccount -Tenant 00000000-0000-0000-0000-000000000000`,
where `00000000-0000-0000-0000-000000000000` should be replaced with your Tenant ID. 

## Enable Windows Server Management across a single tenant

```powershell
Connect-AzAccount
.\Enable-WindowsServerManagementByAzureArc.ps1
```

## Simulate an Enable Windows Server Management across a specific tenant

```powershell
Connect-AzAccount -TenantID '00000000-0000-0000-0000-000000000000'
.\Enable-WindowsServerManagementByAzureArc.ps1 -WhatIf
```

## Enable Windows Server Management on multiple Azure Tenants

```powershell
$TenantID1 = '00000000-0000-0000-0000-000000000000'
$TenantID2 = '11111111-1111-1111-1111-111111111111'
Connect-AzAccount -TenantID $TenantID1
.\Enable-WindowsServerManagementByAzureArc.ps1 -TenantIDs $TenantID1, $TenantID2
```

## Enable Windows Server Management on a specific Management Group

```powershell
Connect-AzAccount -ManagementGroupIDs 'MyOrg_Production'
.\Enable-WindowsServerManagementByAzureArc.ps1
```

## Enable Windows Server Management on multiple Management Groups

```powershell
Connect-AzAccount -ManagementGroupIDs 'MyOrg_Development','MyOrg_Production'
.\Enable-WindowsServerManagementByAzureArc.ps1
```

## Enable Windows Server Management on a Specific Subscription

```powershell
Connect-AzAccount
.\Enable-WindowsServerManagementByAzureArc.ps1 -SubscriptionIDs '00000000-0000-0000-0000-000000000000'
```

## Enable Windows Server Management on Multiple Subscriptions

```powershell
Connect-AzAccount
.\Enable-WindowsServerManagementByAzureArc.ps1 -SubscriptionIDs '00000000-0000-0000-0000-000000000000', '11111111-1111-1111-1111-111111111111'
```

## Enable Windows Server Management on Specific Resource Groups

```powershell
Connect-AzAccount
Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
.\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01'
```

## Enable Windows Server Management on Multiple Resource Groups

```powershell
Connect-AzAccount
Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
.\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01', 'Prod-RG-Arc-02'
```

## Enable a specific server for Windows Server Management

```powershell
Connect-AzAccount
Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
.\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01', 'Prod-RG-Arc-02' -MachineNames 'Server1'
```

## Enable multiple servers in one resource group for Windows Server Management

```powershell
Connect-AzAccount
Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
.\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01' -MachineNames 'Server1', 'Server2'
```
You may additionally omit the Resource Group name is servers names are wholly unique

```powershell
Connect-AzAccount
Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
.\Enable-WindowsServerManagementByAzureArc.ps1 -MachineNames 'Server1', 'Server2'
```

## Enable a set of servers in multiple resource groups for Windows Server Management

```powershell
Connect-AzAccount
Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
.\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01', 'Prod-RG-Arc-02' -MachineNames 'Server1', 'Server2'
```

## Exclude a specific server from Windows Server Management

```powershell
Connect-AzAccount
Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
.\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01' -ExcludeMachineResourceIDs '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Prod-RG-3TierApp-01/providers/Microsoft.HybridCompute/machines/Server3'
```

## Exclude multiple servers from Windows Server Management

```powershell
Connect-AzAccount
Get-AzSubscription -SubscriptionName 'Prod 01' | Set-AzContext
.\Enable-WindowsServerManagementByAzureArc.ps1 -ResourceGroupNames 'Prod-RG-Arc-01' -ExcludeMachineResourceIDs '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Prod-RG-3TierApp-01/providers/Microsoft.HybridCompute/machines/Server3,/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Prod-RG-3TierApp-01/providers/Microsoft.HybridCompute/machines/Server4'
```