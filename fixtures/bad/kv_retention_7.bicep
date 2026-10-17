var tags = {
  owner: 'platform'
  env: 'dev'
}

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-fixture-001'
  location: 'westeurope'
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enablePurgeProtection: true
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}
