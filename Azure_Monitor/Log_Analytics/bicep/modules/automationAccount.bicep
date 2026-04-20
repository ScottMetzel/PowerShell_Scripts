@description('Azure region for all resources.')
param location string

@description('Name of the Automation Account.')
param automationAccountName string

@description('URI of the PowerShell runbook script.')
param runbookScriptUri string

resource automationAccount 'Microsoft.Automation/automationAccounts@2023-11-01' = {
  name: automationAccountName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    sku: {
      name: 'Basic'
    }
  }
}

@description('The principal ID of the Automation Account system-assigned managed identity.')
output principalId string = automationAccount.identity.principalId

@description('The resource ID of the Automation Account.')
output automationAccountId string = automationAccount.id

// Runtime Environment with PowerShell 7.6
resource runtimeEnvironment 'Microsoft.Automation/automationAccounts/runtimeEnvironments@2023-05-15-preview' = {
  parent: automationAccount
  name: 'ps76-runtime'
  location: location
  properties: {
    runtime: {
      language: 'PowerShell'
      version: '7.6'
    }
    defaultPackages: {
      'Az.Accounts': 'latest'
    }
  }
}

// Gallery packages for the runtime environment
resource azOperationalInsightsPackage 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2023-05-15-preview' = {
  parent: runtimeEnvironment
  name: 'Az.OperationalInsights'
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/Az.OperationalInsights'
    }
  }
}

resource azResourcesPackage 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2023-05-15-preview' = {
  parent: runtimeEnvironment
  name: 'Az.Resources'
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/Az.Resources'
    }
  }
}

resource azStoragePackage 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2023-05-15-preview' = {
  parent: runtimeEnvironment
  name: 'Az.Storage'
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/Az.Storage'
    }
  }
}

// PowerShell Runbook using the Runtime Environment
resource runbook 'Microsoft.Automation/automationAccounts/runbooks@2023-11-01' = {
  parent: automationAccount
  name: 'Export-LAToBlob'
  location: location
  properties: {
    runbookType: 'PowerShell'
    publishContentLink: {
      uri: runbookScriptUri
    }
    logVerbose: true
    logProgress: true
  }
}
