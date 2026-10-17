param environment string = 'dev'

module storage 'storage_module.bicep' = {
  name: 'storage'
  params: {
    httpsOnly: true
    tlsVersion: environment == 'prod' ? 'TLS1_2' : 'TLS1_0'
  }
}
