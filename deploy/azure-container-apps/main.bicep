// tresor-server on Azure Container Apps (spec 002): several replicas on PostgreSQL or Azure SQL, the KEK in
// Key Vault, everything reached with one user-assigned managed identity - no password, no secret of the
// service's own. Deploy into a resource group:
//
//   az deployment group create -g <rg> -f main.bicep -p database=postgres issuers=... admins=...
//
// See README.md for what each parameter means, and for tightening it for production.

@description('Where everything goes.')
param location string = resourceGroup().location

@description('A short prefix of every resource name: lower-case letters and digits, a letter first.')
@minLength(2)
@maxLength(12)
param prefix string = 'tresor'

@description('The image: ghcr.io/hugr-lab/tresor-server:<tag>.')
param image string = 'ghcr.io/hugr-lab/tresor-server:edge'

@description('The state store: postgres (Azure Database for PostgreSQL, Burstable B1ms) or sqlserver (Azure SQL, Basic).')
@allowed(['postgres', 'sqlserver'])
param database string = 'postgres'

@description('The identity providers, as the TRESOR_ISSUERS YAML list: [{issuer: ..., audience: ..., ...}].')
param issuers string

@description('The admins, as the TRESOR_POLICY__ADMINS YAML list: [role:secrets_admin, ...].')
param admins string

@description('The servers allowed to act for users, as the TRESOR_POLICY__ACTORS YAML list (default none).')
param actors string = '[]'

@description('Where references (ref+azkv://) may read, as the TRESOR_MATERIAL__AZKV__ALLOW YAML list; default: this deployment\'s vault, names starting duckdb-.')
param materialAllow string = ''

@description('Replicas: at least two on a database.')
@minValue(1)
param minReplicas int = 2
param maxReplicas int = 3

var p = toLower(prefix) // Container Apps, database and vault names are lower-case
var suffix = uniqueString(resourceGroup().id, p)
var vaultName = take('${p}kv${suffix}', 24)
var dbName = 'tresor'

// --- identity ----------------------------------------------------------------------------------------------

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${p}-id-${suffix}'
  location: location
}

// --- the KEK and the vault of references -------------------------------------------------------------------

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  properties: {
    tenantId: tenant().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enablePurgeProtection: true // the KEK must never be deleted for good by mistake: the material depends on it
  }
}

resource kek 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
  parent: vault
  name: 'tresor-kek'
  properties: {
    kty: 'RSA'
    keySize: 3072
    keyOps: ['wrapKey', 'unwrapKey', 'sign'] // sign: the root that authenticates data keys (spec 003)
  }
}

// get, wrapKey, unwrapKey and sign - exactly what the service does with its KEK, on that key only. No built-in
// role gives exactly this: Crypto Service Encryption User has no sign (the root that authenticates data keys,
// spec 003), Crypto User adds encrypt and decrypt
resource kekRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, p, 'tresor-kek-user')
  properties: {
    roleName: 'tresor KEK user (${p}, ${resourceGroup().name})'
    description: 'tresor-server: get, wrap, unwrap and sign with its key-encryption key'
    type: 'CustomRole'
    assignableScopes: [resourceGroup().id]
    permissions: [
      {
        actions: []
        dataActions: [
          'Microsoft.KeyVault/vaults/keys/read'
          'Microsoft.KeyVault/vaults/keys/wrap/action'
          'Microsoft.KeyVault/vaults/keys/unwrap/action'
          'Microsoft.KeyVault/vaults/keys/sign/action'
        ]
      }
    ]
  }
}

resource kekRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kek.id, identity.id, 'tresor-kek-user')
  scope: kek
  properties: {
    roleDefinitionId: kekRoleDefinition.id
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Key Vault Secrets User: reads secrets - on this vault (other vaults in the allowlist need the same role)
resource secretsRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, identity.id, 'secrets-user')
  scope: vault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// --- the database: Entra only, the identity its administrator ----------------------------------------------

module pg 'modules/postgres.bicep' = if (database == 'postgres') {
  name: 'postgres'
  params: {
    location: location
    name: '${p}-pg-${suffix}'
    dbName: dbName
    identityName: identity.name
    principalId: identity.properties.principalId
  }
}

module sql 'modules/sqlserver.bicep' = if (database == 'sqlserver') {
  name: 'sqlserver'
  params: {
    location: location
    name: '${p}-sql-${suffix}'
    dbName: dbName
    identityName: identity.name
    clientId: identity.properties.clientId
  }
}

var dsn = pg.?outputs.dsn ?? sql.?outputs.dsn ?? ''

// --- Container Apps ----------------------------------------------------------------------------------------

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${p}-logs-${suffix}'
  location: location
  properties: { sku: { name: 'PerGB2018' }, retentionInDays: 30 }
}

resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${p}-env-${suffix}'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
  }
}

var appName = '${p}-app'

// the service's settings: the app's and the maintenance jobs' (spec 019), one identity and one configuration
var serviceEnv = [
  { name: 'TRESOR_LISTEN', value: '0.0.0.0:8080' }
  { name: 'TRESOR_PUBLIC_URL', value: 'https://${appName}.${env.properties.defaultDomain}' }
  { name: 'TRESOR_TLS__OFFLOAD', value: 'true' }
  { name: 'TRESOR_STATE__KIND', value: database }
  { name: 'TRESOR_STATE__DSN', value: dsn }
  { name: 'TRESOR_STATE__AUTH', value: 'entra' }
  { name: 'TRESOR_KEYS__KIND', value: 'azurekeyvault' }
  { name: 'TRESOR_KEYS__KEY', value: '${vault.properties.vaultUri}keys/${kek.name}' }
  { name: 'TRESOR_AZURE__IDENTITY', value: 'managed' }
  { name: 'TRESOR_AZURE__CLIENT_ID', value: identity.properties.clientId }
  { name: 'TRESOR_ISSUERS', value: issuers }
  { name: 'TRESOR_POLICY__ADMINS', value: admins }
  { name: 'TRESOR_POLICY__ACTORS', value: actors }
  {
    name: 'TRESOR_MATERIAL__AZKV__ALLOW'
    value: empty(materialAllow) ? '[{vault: ${vault.name}, prefixes: [duckdb-]}]' : materialAllow
  }
]


resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: appName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identity.id}': {} }
  }
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8080
        transport: 'http'
        allowInsecure: false // https only: TLS ends here (tls.offload)
      }
    }
    template: {
      containers: [
        {
          name: 'tresor-server'
          image: image
          resources: { cpu: json('0.25'), memory: '0.5Gi' }
          env: serviceEnv
          probes: [
            { type: 'Liveness', httpGet: { path: '/healthz', port: 8080 }, periodSeconds: 10 }
            { type: 'Readiness', httpGet: { path: '/readyz', port: 8080 }, periodSeconds: 10, failureThreshold: 3 }
            { type: 'Startup', httpGet: { path: '/healthz', port: 8080 }, periodSeconds: 5, failureThreshold: 30 }
          ]
        }
      ]
      scale: { minReplicas: minReplicas, maxReplicas: maxReplicas }
    }
  }
  dependsOn: [kekRole, secretsRole] // the database: through its DSN
}

// --- the commands as jobs (spec 019): manual, the app's image, identity and settings ---------------------------
//   az containerapp job start -g <rg> -n <prefix>-reseal       (then: az containerapp job execution list)
var commands = {
  reseal: ['reseal', '-retire']
  'reseal-rotate': ['reseal', '-rotate', '-retire']
  rewrap: ['rewrap']
  refs: ['refs', '-resolve']
  mac: ['mac']
}

resource jobs 'Microsoft.App/jobs@2024-03-01' = [for c in items(commands): {
  name: '${p}-${c.key}'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identity.id}': {} }
  }
  properties: {
    environmentId: env.id
    configuration: {
      triggerType: 'Manual'
      replicaTimeout: 3600
      replicaRetryLimit: 0 // a command is not retried: its log says what to do
      manualTriggerConfig: { parallelism: 1, replicaCompletionCount: 1 }
    }
    template: {
      containers: [
        {
          name: 'tresor-server'
          image: image
          args: c.value
          resources: { cpu: json('0.25'), memory: '0.5Gi' }
          env: serviceEnv
        }
      ]
    }
  }
  dependsOn: [kekRole, secretsRole]
}]

output url string = 'https://${app.properties.configuration.ingress.fqdn}'
output vault string = vault.name
output identityClientId string = identity.properties.clientId
output dsn string = dsn
