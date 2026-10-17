param environment string = 'dev'

module storage 'storage_module.bicep' = {
  name: 'storage'
  params: {
    httpsOnly: true
    tlsVersion: 'TLS1_0'
  }
}
