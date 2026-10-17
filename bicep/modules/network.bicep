param name string
param location string = resourceGroup().location
param tags object

@description('Where administrators connect from, for example a bastion or office range. Never the whole internet.')
param adminSourcePrefix string

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'allow-https-in'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
      {
        name: 'allow-ssh-from-admins'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: adminSourcePrefix
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
    ]
  }
}

output id string = nsg.id
