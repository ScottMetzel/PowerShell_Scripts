@description('Azure region for all resources.')
param location string

@description('Name of the Function App.')
param functionAppName string

@description('Name of the App Service Plan.')
param appServicePlanName string

@description('Name of the Application Insights resource.')
param applicationInsightsName string

@description('Name of the existing storage account used by the Function App for internal operations (e.g., triggers, logging).')
@minLength(3)
@maxLength(24)
param storageAccountName string

@description('URI of the PowerShell script to use in the Function App.')
param scriptUri string = 'https://raw.githubusercontent.com/ScottMetzel/PowerShell_Scripts/refs/heads/main/Azure_Monitor/Log_Analytics/Export-LAToBlob.ps1'

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' existing = {
  name: storageAccountName
}

resource appServicePlan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: appServicePlanName
  location: location
  kind: 'functionapp'
  sku: {
    name: 'Standard'
  }
}

resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: applicationInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
}

resource functionApp 'Microsoft.Web/sites@2024-04-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      powerShellVersion: '7.4'
      use32BitWorkerProcess: false
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower(functionAppName)
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'powershell'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: applicationInsights.properties.InstrumentationKey
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: applicationInsights.properties.ConnectionString
        }
        {
          name: 'SCRIPT_URI'
          value: scriptUri
        }
      ]
    }
  }
}

@description('The principal ID of the Function App system-assigned managed identity.')
output principalId string = functionApp.identity.principalId

@description('The resource ID of the Function App.')
output functionAppId string = functionApp.id

@description('The default hostname of the Function App.')
output defaultHostName string = functionApp.properties.defaultHostName
