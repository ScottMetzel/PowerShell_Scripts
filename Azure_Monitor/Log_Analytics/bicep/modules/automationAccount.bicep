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
      name: 'Free'
    }
  }
}

@description('The principal ID of the Automation Account system-assigned managed identity.')
output principalId string = automationAccount.identity.principalId

@description('The resource ID of the Automation Account.')
output automationAccountId string = automationAccount.id

// Runtime Environment with PowerShell 7.6
resource runtimeEnvironment 'Microsoft.Automation/automationAccounts/runtimeEnvironments@2024-10-23' = {
  parent: automationAccount
  name: 'PowerShell_7-6'
  location: location
  properties: {
    runtime: {
      language: 'PowerShell'
      version: '7.6'
    }
    defaultPackages: {}
  }
}

// Gallery packages for the runtime environment
resource AARuntimeEnvAz 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2024-10-23' = {
  parent: runtimeEnvironment
  name: 'Az'
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/Az/15.5.0'
    }
  }
}

resource AARuntimeEnvAzAccounts 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2024-10-23' = {
  parent: runtimeEnvironment
  name: 'Az.Accounts'
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/Az.Accounts/5.3.4'
    }
  }
}

resource AARuntimeEnvAzOperationalInsights 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2024-10-23' = {
  parent: runtimeEnvironment
  name: 'Az.OperationalInsights'
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/Az.OperationalInsights/3.3.0'
    }
  }
}

resource AARuntimeEnvAzResources 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2024-10-23' = {
  parent: runtimeEnvironment
  name: 'Az.Resources'
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/Az.Resources/9.0.3'
    }
  }
}

resource AARuntimeEnvAzStorage 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2024-10-23' = {
  parent: runtimeEnvironment
  name: 'Az.Storage'
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/Az.Storage/9.6.0'
    }
  }
}

// PowerShell Runbook using the Runtime Environment
resource runbook 'Microsoft.Automation/automationAccounts/runbooks@2024-10-23' = {
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
    runtimeEnvironment: runtimeEnvironment.name
  }
}
