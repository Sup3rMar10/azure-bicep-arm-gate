var tags = {
  owner: 'platform'
  env: 'dev'
}

resource account 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'stfixture001'
  location: 'westeurope'
  kind: 'StorageV2'
  sku: {
    name: 'Standard_ZRS'
  }
  properties: {
    supportsHttpsTrafficOnly: false
    minimumTlsVersion: 'TLS1_0'
    allowBlobPublicAccess: true
    allowSharedKeyAccess: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}
