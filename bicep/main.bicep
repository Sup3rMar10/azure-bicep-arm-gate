targetScope = 'resourceGroup'

@description('Short name used as a prefix for every resource.')
@minLength(3)
@maxLength(12)
param prefix string

@allowed(['dev', 'staging', 'prod'])
param environment string = 'dev'

@description('Where administrators connect from. Required: there is deliberately no default.')
param adminSourcePrefix string

var tags = {
  owner: 'platform'
  env: environment
}

module storage 'modules/storage.bicep' = {
  name: 'storage'
  params: {
    name: take(toLower('${prefix}${environment}st${uniqueString(resourceGroup().id)}'), 24)
    tags: tags
  }
}

module vault 'modules/keyvault.bicep' = {
  name: 'vault'
  params: {
    name: '${prefix}-${environment}-kv-${take(uniqueString(resourceGroup().id), 5)}'
    tags: tags
  }
}

module network 'modules/network.bicep' = {
  name: 'network'
  params: {
    name: '${prefix}-${environment}-nsg'
    tags: tags
    adminSourcePrefix: adminSourcePrefix
  }
}

module web 'modules/webapp.bicep' = {
  name: 'web'
  params: {
    name: '${prefix}-${environment}-web'
    tags: tags
  }
}

output storageId string = storage.outputs.id
