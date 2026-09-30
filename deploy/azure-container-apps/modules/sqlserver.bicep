// Azure SQL, Entra only, with the service's identity as its administrator.
param location string
param name string
param dbName string
param identityName string
@description('The identity\'s client (application) id: an Application administrator\'s sid is its client id.')
param clientId string
@description('The database\'s sku. Basic is the smallest; the service\'s readiness checks keep a serverless one from ever pausing.')
param sku object = { name: 'Basic', tier: 'Basic' }

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
      sid: clientId
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
  sku: sku
  dependsOn: [allowAzure]
}

output dsn string = 'sqlserver://${sql.properties.fullyQualifiedDomainName}?database=${dbName}&encrypt=true'
