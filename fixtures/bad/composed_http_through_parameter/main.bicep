param environment string = 'dev'

module storage 'storage_module.bicep' = {
  name: 'storage'
  params: {
    httpsOnly: false
    tlsVersion: 'TLS1_2'
  }
}
