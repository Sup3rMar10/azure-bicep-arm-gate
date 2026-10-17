param httpsOnly bool
param tlsVersion string

resource account 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'stmodule001'
  location: 'westeurope'
  tags: {
    owner: 'platform'
    env: 'dev'
  }
  kind: 'StorageV2'
  sku: {
    name: 'Standard_ZRS'
  }
  properties: {
    supportsHttpsTrafficOnly: httpsOnly
    minimumTlsVersion: tlsVersion
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}
