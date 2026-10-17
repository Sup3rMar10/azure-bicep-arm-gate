var tags = {
  owner: 'platform'
  env: 'dev'
}

resource account 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'stfixture001'
  location: 'westeurope'
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: 'Standard_ZRS'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: true
    allowSharedKeyAccess: false
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}
