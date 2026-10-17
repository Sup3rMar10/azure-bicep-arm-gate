var tags = {
  owner: 'platform'
  env: 'dev'
}

resource site 'Microsoft.Web/sites@2023-12-01' = {
  name: 'web-fixture-001'
  location: 'westeurope'
  tags: tags
  kind: 'app,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Web/serverfarms/plan'
    httpsOnly: true
    siteConfig: {
      minTlsVersion: '1.1'
      ftpsState: 'Disabled'
    }
  }
}
