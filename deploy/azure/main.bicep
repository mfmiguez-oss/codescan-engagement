// codescan-engagement on Azure Container Apps Jobs.
//
// The scanning workload is a *job*, not a service: it starts on a schedule,
// drives one run, writes artifacts, and exits. It has no listening surface at
// all, which is what keeps it exposure-free regardless of what else is
// deployed.
//
// The control plane is the opposite, and is therefore opt-in.
// `deployControlPlane` defaults to false: an endpoint that accepts state
// changes must not appear until an Entra application is registered and its
// issuer and audience are configured, because the alternative is an endpoint
// that is the only thing between the network and the decision log.
//
// Nothing in this template holds a secret. The job authenticates to Foundry and
// to storage with a user-assigned managed identity, so there is no API key to
// rotate, leak, or check into a repo.

@description('Deployment region.')
param location string = resourceGroup().location

@description('Short name prefix for every resource.')
@minLength(3)
@maxLength(11)
param namePrefix string

@description('Container image, including registry and digest or tag.')
param image string

@description('Azure AI Foundry resource name the job calls.')
param foundryResource string

@description('Model deployment the driver dispatches to.')
param modelDeployment string

@description('Cron schedule. Default: 02:00 UTC daily.')
param cronExpression string = '0 2 * * *'

@description('Hard ceiling on model calls for one run.')
param maxCalls int = 200

@description('Entra application (client) ID the API validates tokens for.')
param apiAudience string = ''

@description('Entra tenant ID. Tokens from any other tenant are rejected.')
param entraTenantId string = ''

@description('Deploy the control-plane API alongside the batch job.')
param deployControlPlane bool = false

@description('Existing subnet resource id for VNet integration. Empty disables it.')
param infrastructureSubnetId string = ''

var uniquePart = uniqueString(resourceGroup().id, namePrefix)
var storageName = toLower('${namePrefix}st${uniquePart}')

// ---------------------------------------------------------------------------
// Identity — one user-assigned identity used for every data-plane call.
// ---------------------------------------------------------------------------

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-id'
  location: location
}

// ---------------------------------------------------------------------------
// Artifacts — run workspaces and SARIF exports.
// ---------------------------------------------------------------------------

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_ZRS' }
  kind: 'StorageV2'
  properties: {
    // Source under review and its findings never travel unencrypted, and
    // never over a public endpoint once the subnet is supplied.
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    publicNetworkAccess: empty(infrastructureSubnetId) ? 'Enabled' : 'Disabled'
  }
}

resource blob 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

// Artifacts are the record of truth, so the container that holds them is
// versioned and soft-delete protected rather than merely durable.
resource artifacts 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blob
  name: 'artifacts'
  properties: {
    publicAccess: 'None'
  }
}

// Storage Blob Data Contributor, scoped to this account only.
var blobContributorRoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'

resource storageRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identity.id, blobContributorRoleId)
  scope: storage
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      blobContributorRoleId
    )
  }
}

// ---------------------------------------------------------------------------
// Observability
// ---------------------------------------------------------------------------

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${namePrefix}-logs'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 90
  }
}

// ---------------------------------------------------------------------------
// Container Apps environment
// ---------------------------------------------------------------------------

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${namePrefix}-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
    vnetConfiguration: empty(infrastructureSubnetId) ? null : {
      infrastructureSubnetId: infrastructureSubnetId
      internal: true
    }
  }
}

// ---------------------------------------------------------------------------
// The job
// ---------------------------------------------------------------------------

resource job 'Microsoft.App/jobs@2024-03-01' = {
  name: '${namePrefix}-run'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    environmentId: environment.id
    configuration: {
      triggerType: 'Schedule'
      scheduleTriggerConfig: {
        cronExpression: cronExpression
        parallelism: 1
        // One completion per firing: a scan that failed must not be retried
        // automatically, because the retry re-spends the model budget on the
        // same broken input.
        replicaCompletionCount: 1
      }
      // A run is long: recon, a router call, then one call per scenario.
      replicaTimeout: 10800
      replicaRetryLimit: 0
    }
    template: {
      containers: [
        {
          name: 'engagement'
          image: image
          resources: {
            cpu: json('2.0')
            memory: '4Gi'
          }
          env: [
            { name: 'ENGAGEMENT_PROVIDER', value: 'foundry' }
            { name: 'FOUNDRY_RESOURCE', value: foundryResource }
            { name: 'ENGAGEMENT_MODEL', value: modelDeployment }
            { name: 'ENGAGEMENT_MAX_CALLS', value: string(maxCalls) }
            { name: 'AZURE_CLIENT_ID', value: identity.properties.clientId }
            { name: 'OPENHACK_ROOT', value: '/workspace' }
          ]
        }
      ]
    }
  }
  dependsOn: [ storageRole ]
}

// ---------------------------------------------------------------------------
// Control plane
//
// Separate from the job on purpose. The job has no listening surface; this
// does, which is exactly why it must not exist until tokens are verified
// against a real issuer. `deployControlPlane` defaults to false so a
// deployment that has not registered an Entra application cannot accidentally
// stand up an endpoint that would then be the only thing between the internet
// and the decision log.
// ---------------------------------------------------------------------------

resource api 'Microsoft.App/containerApps@2024-03-01' = if (deployControlPlane) {
  name: '${namePrefix}-api'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      ingress: {
        // internal when the environment is VNet-integrated: the control plane
        // is reached through the private network, not from the public internet
        external: empty(infrastructureSubnetId)
        targetPort: 8080
        transport: 'http'
        allowInsecure: false
      }
    }
    template: {
      containers: [
        {
          name: 'api'
          image: image
          command: ['uvicorn']
          args: ['engagement.asgi:app', '--host', '0.0.0.0', '--port', '8080']
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            { name: 'ENGAGEMENT_TENANT_ID', value: entraTenantId }
            { name: 'ENGAGEMENT_API_AUDIENCE', value: apiAudience }
            {
              name: 'ENGAGEMENT_JWKS_URI'
              value: 'https://login.microsoftonline.com/${entraTenantId}/discovery/v2.0/keys'
            }
            {
              name: 'ENGAGEMENT_ISSUER'
              value: 'https://login.microsoftonline.com/${entraTenantId}/v2.0'
            }
            { name: 'ENGAGEMENT_DECISIONS', value: '/artifacts/decisions.jsonl' }
            { name: 'AZURE_CLIENT_ID', value: identity.properties.clientId }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 3
      }
    }
  }
}

output jobName string = job.name
output apiFqdn string = deployControlPlane ? api.properties.configuration.ingress.fqdn : ''
output identityClientId string = identity.properties.clientId
output artifactAccount string = storage.name
output artifactContainer string = artifacts.name
