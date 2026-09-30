// Azure SQL, Entra only, with the service's identity as its administrator; a serverless database.
param location string
param name string
param dbName string
param identityName string
param principalId string

resource sql 'Microsoft.Sql/servers@2023-08-01' = {
  name: name
  location: location
  properties: {
    minimalTlsVersion: '1.2'
    publicNetworkAccess: 'Enabled'
    administrators: {
      administratorType: 'ActiveDirectory'
      azureADOnlyAuthentication: true
      login: identityName
      sid: principalId
      principalType: 'Application'
      tenantId: tenant().tenantId
    }
  }
}

resource allowAzure 'Microsoft.Sql/servers/firewallRules@2023-08-01' = {
  parent: sql
  name: 'AllowAzureServices'
  properties: { startIpAddress: '0.0.0.0', endIpAddress: '0.0.0.0' }
}

resource db 'Microsoft.Sql/servers/databases@2023-08-01' = {
  parent: sql
  name: dbName
  location: location
  sku: { name: 'GP_S_Gen5_1', tier: 'GeneralPurpose' }
  properties: {
    autoPauseDelay: 60 // serverless: it pauses when idle; the first request after waits for it to resume
    minCapacity: json('0.5')
  }
  dependsOn: [allowAzure]
}

output dsn string = 'sqlserver://${sql.properties.fullyQualifiedDomainName}?database=${dbName}&encrypt=true'
