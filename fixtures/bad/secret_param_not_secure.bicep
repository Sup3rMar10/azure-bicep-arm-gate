param adminPassword string
param adminUser string = 'azureuser'

resource account 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'stsecret001'
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
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}

output user string = adminUser
output passwordLength int = length(adminPassword)
