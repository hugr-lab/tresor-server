// Azure Database for PostgreSQL Flexible Server, Entra only, with the service's identity as its administrator
// (a module: the administrator's name is the identity's object id, known only once the identity exists).
param location string
param name string
param dbName string
param identityName string
param principalId string

resource pg 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: name
  location: location
  sku: { name: 'Standard_B1ms', tier: 'Burstable' }
  properties: {
    version: '16'
    storage: { storageSizeGB: 32 }
    authConfig: { activeDirectoryAuth: 'Enabled', passwordAuth: 'Disabled', tenantId: tenant().tenantId }
    network: { publicNetworkAccess: 'Enabled' }
    highAvailability: { mode: 'Disabled' }
    backup: { backupRetentionDays: 7, geoRedundantBackup: 'Disabled' }
  }
}

resource allowAzure 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2024-08-01' = {
  parent: pg
  name: 'AllowAzureServices' // Container Apps without a VNet; a private endpoint is the production way
  properties: { startIpAddress: '0.0.0.0', endIpAddress: '0.0.0.0' }
}

resource db 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
  parent: pg
  name: dbName
  dependsOn: [allowAzure] // one operation at a time on a flexible server
}

resource admin 'Microsoft.DBforPostgreSQL/flexibleServers/administrators@2024-08-01' = {
  parent: pg
  name: principalId
  properties: {
    principalName: identityName
    principalType: 'ServicePrincipal'
    tenantId: tenant().tenantId
  }
  dependsOn: [db, allowAzure]
}

// the identity logs in as its administrator role, named as the identity; the server's certificate checked
output dsn string = 'host=${pg.properties.fullyQualifiedDomainName} user=${identityName} dbname=${dbName} sslmode=verify-full'
