targetScope = 'subscription'

@description('Azure region for all resources.')
param location string = 'westus2'

@description('Short environment name used as a prefix for all resource names.')
@allowed([
  'Demo'
  'Dev'
  'Test'
  'Staging'
  'Prod'
])
param environmentName string = 'Prod'

@description('Base name prefix for resource groups and automation accounts.')
param baseName string = 'LAExport'

@description('URI of the PowerShell runbook script.')
param runbookScriptUri string = 'https://raw.githubusercontent.com/ScottMetzel/PowerShell_Scripts/refs/heads/main/Azure_Monitor/Log_Analytics/Export-LAToBlob.ps1'

@description('Number of resource groups and automation accounts to create.')
@minValue(1)
@maxValue(10)
param instanceCount int = 10

@description('The name of the storage account to create for storing logs. Must be globally unique across Azure.')
@minLength(3)
@maxLength(24)
param storageAccountName string

@description('The name of the blob container to create within the storage account.')
@minLength(3)
@maxLength(63)
param containerName string

// Role definition IDs (built-in)
var logAnalyticsReaderRoleId = '73c42c96-874c-492b-b04d-ab87d138a893'
var storageAccountContributorRoleId = '17d1049b-9a84-46fb-8f53-869881c3d3ab'
var storageBlobDataContributorRoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'

resource resourceGroups 'Microsoft.Resources/resourceGroups@2025-04-01' = [
  for i in range(1, instanceCount): {
    name: '${environmentName}-RG-${baseName}-${padLeft(i, 2, '0')}'
    location: location
  }
]

module functionAppDeployments './modules/functionApp.bicep' = [
  for i in range(1, instanceCount): {
    scope: resourceGroups[i - 1]
    params: {
      location: location
      functionAppName: '${environmentName}-FA-${baseName}-${padLeft(i, 2, '0')}'
      appServicePlanName: '${environmentName}-ASP-${baseName}-${padLeft(i, 2, '0')}'
      applicationInsightsName: '${environmentName}-AI-${baseName}-${padLeft(i, 2, '0')}'
      storageAccountName: toLower(storageAccountName)
      scriptUri: runbookScriptUri
    }
  }
]

module storageAccountDeployments './modules/storageAccount.bicep' = [
  for i in range(1, instanceCount): {
    scope: resourceGroups[i - 1]
    params: {
      location: location
      storageAccountName: toLower(storageAccountName)
      containerName: containerName
      allowStorageAccountKeyAccess: false
    }
  }
]

// Subscription-scoped role assignments for each Automation Account's managed identity
resource logAnalyticsReaderAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for i in range(1, instanceCount): {
    name: guid(subscription().id, '${environmentName}-FA-${baseName}-${padLeft(i, 2, '0')}', logAnalyticsReaderRoleId)
    properties: {
      principalId: functionAppDeployments[i - 1].outputs.principalId
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', logAnalyticsReaderRoleId)
      principalType: 'ServicePrincipal'
    }
  }
]

resource storageAccountContributorAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for i in range(1, instanceCount): {
    name: guid(
      subscription().id,
      '${environmentName}-FA-${baseName}-${padLeft(i, 2, '0')}',
      storageAccountContributorRoleId
    )
    properties: {
      principalId: functionAppDeployments[i - 1].outputs.principalId
      roleDefinitionId: subscriptionResourceId(
        'Microsoft.Authorization/roleDefinitions',
        storageAccountContributorRoleId
      )
      principalType: 'ServicePrincipal'
    }
  }
]

resource storageBlobDataContributorAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for i in range(1, instanceCount): {
    name: guid(
      subscription().id,
      '${environmentName}-FA-${baseName}-${padLeft(i, 2, '0')}',
      storageBlobDataContributorRoleId
    )
    properties: {
      principalId: functionAppDeployments[i - 1].outputs.principalId
      roleDefinitionId: subscriptionResourceId(
        'Microsoft.Authorization/roleDefinitions',
        storageBlobDataContributorRoleId
      )
      principalType: 'ServicePrincipal'
    }
  }
]
