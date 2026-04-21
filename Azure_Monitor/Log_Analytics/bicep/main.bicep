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

module automationDeployments './modules/automationAccount.bicep' = [
  for i in range(1, instanceCount): {
    scope: resourceGroups[i - 1]
    params: {
      location: location
      automationAccountName: '${environmentName}-AA-${baseName}-${padLeft(i, 2, '0')}'
      runbookScriptUri: runbookScriptUri
    }
  }
]

// Subscription-scoped role assignments for each Automation Account's managed identity
resource logAnalyticsReaderAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for i in range(1, instanceCount): {
    name: guid(subscription().id, '${environmentName}-AA-${baseName}-${padLeft(i, 2, '0')}', logAnalyticsReaderRoleId)
    properties: {
      principalId: automationDeployments[i - 1].outputs.principalId
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', logAnalyticsReaderRoleId)
      principalType: 'ServicePrincipal'
    }
  }
]

resource storageAccountContributorAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for i in range(1, instanceCount): {
    name: guid(
      subscription().id,
      '${environmentName}-AA-${baseName}-${padLeft(i, 2, '0')}',
      storageAccountContributorRoleId
    )
    properties: {
      principalId: automationDeployments[i - 1].outputs.principalId
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
      '${environmentName}-AA-${baseName}-${padLeft(i, 2, '0')}',
      storageBlobDataContributorRoleId
    )
    properties: {
      principalId: automationDeployments[i - 1].outputs.principalId
      roleDefinitionId: subscriptionResourceId(
        'Microsoft.Authorization/roleDefinitions',
        storageBlobDataContributorRoleId
      )
      principalType: 'ServicePrincipal'
    }
  }
]
