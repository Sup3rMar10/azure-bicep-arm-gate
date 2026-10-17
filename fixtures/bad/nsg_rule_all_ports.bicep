resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' existing = {
  name: 'nsg-existing'
}

resource adminRule 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: nsg
  name: 'allow-admin'
  properties: {
    priority: 200
    direction: 'Inbound'
    access: 'Allow'
    protocol: 'Tcp'
    sourceAddressPrefix: '*'
    sourcePortRange: '*'
    destinationAddressPrefix: '*'
    destinationPortRange: '*'
  }
}
