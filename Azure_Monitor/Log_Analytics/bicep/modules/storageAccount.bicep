@description('The name of the storage account. Must be 3-24 characters, lowercase letters and numbers only.')
@minLength(3)
@maxLength(24)
param storageAccountName string

@description('The name of the blob container to create within the storage account.')
@minLength(3)
@maxLength(63)
param containerName string

@description('The location for the storage account.')
param location string = resourceGroup().location

@description('The SKU name for the storage account.')
param skuName string = 'Standard_LRS'

@description('Allow or disallow storage account key (Shared Key) authorization. When false, all requests must be authorized with Azure AD.')
param allowStorageAccountKeyAccess bool = true

@description('Allow or disallow SAS token usage. When false, a SAS policy with a Block expiration action is enforced with a 1-day expiration period.')
param allowSasTokenUsage bool = true

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: skuName
  }
  properties: {
    accessTier: 'Hot'
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: allowStorageAccountKeyAccess
    defaultToOAuthAuthentication: true
    sasPolicy: !allowSasTokenUsage
      ? {
          expirationAction: 'Block'
          sasExpirationPeriod: '1.00:00:00'
        }
      : null
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' existing = {
  parent: storageAccount
  name: 'default'
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: containerName
  properties: {
    publicAccess: 'None'
  }
}

output storageAccountId string = storageAccount.id
output storageAccountName string = storageAccount.name
output containerName string = container.name
output blobEndpoint string = storageAccount.properties.primaryEndpoints.blob
