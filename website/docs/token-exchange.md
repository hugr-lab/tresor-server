---
title: Token exchange
---

# Token exchange

A `token_exchange` secret (tresor specs/010) makes the service mint a token for its caller at the caller's
identity provider (RFC 8693). The service logs in to the IdP as a confidential client, and is configured per
issuer:

```yaml
issuers:
  - issuer: https://idp.example/realms/corp
    audience: duckdb-secrets
    exchange:
      client_id: duckdb-secrets
      client_auth: secret          # secret | azure | file | keyvault | key_file
      client_secret_env: TRESOR_EXCHANGE_SECRET
```

Every way but `secret` needs no secret of the service's own (spec 006).

| `client_auth` | What the service sends | For |
| --- | --- | --- |
| `secret` (default) | the client secret from `client_secret_env` | any IdP |
| `azure` | a token of its Azure identity (`azure.identity`: managed or workload), for a federated credential | Entra |
| `file` | the token in `assertion_file`, read at each request: a projected ServiceAccount token | Keycloak, any IdP trusting the cluster's issuer |
| `keyvault` | a JWT it signs with `key` in Key Vault (RS256 or ES256), as `kid` | any IdP with `private_key_jwt`, on Azure |
| `key_file` | a JWT it signs with `key_file`: ZITADEL's key file, or a PEM key with `kid` | ZITADEL; any IdP with `private_key_jwt`, with no KMS |

- **Signed JWTs**: `iss` and `sub` are the client id, plus a fresh `jti`, valid for one minute. The header
  names the key by `kid`, and by `x5t` (a certificate's thumbprint) when it is set.
  - `aud` is the issuer by default; `assertion_audience: token_endpoint` makes it the token endpoint, which
    Entra wants.
  - A new one is made for each request: an IdP may refuse a `jti` it has seen.
- **No assertion, no request**: if the service cannot make one, the mint fails (`503`). It never falls back
  to a secret or to no authentication.
- **Readiness** has a check `exchange <issuer>` per issuer: it makes an assertion. A failure there is
  *degraded*, not unready: only `token_exchange` secrets depend on it.

## Entra: a federated credential

The service's app registration trusts the service's own Azure identity, with no client secret.

```yaml
exchange: {client_id: <the app registration's client id>, client_auth: azure}
azure: {identity: managed}         # Container Apps; workload on AKS
```

1. On the app registration, add a federated credential of the kind *Managed identity*, naming the service's
   user-assigned identity. This holds on Container Apps and on AKS alike: the assertion is the identity's
   Entra token.
2. The service asks its identity for a token with the audience `api://AzureADTokenExchange`, and sends it as
   the client assertion.

- **On AKS, an alternative**: the federated credential trusts the cluster's OIDC issuer and the
  ServiceAccount's subject. The service then sends the pod's projected token itself: `client_auth: file`,
  `assertion_file` the path in `AZURE_FEDERATED_TOKEN_FILE`.
- **Sovereign clouds** use another audience. This build sends the public cloud's.

### Entra with a certificate (`keyvault`)

```yaml
exchange:
  client_id: <the app registration's client id>
  client_auth: keyvault
  key: https://corp-kv.vault.azure.net/keys/tresor-exchange
  x5t: <the certificate's SHA-1 thumbprint, base64url>
  assertion_audience: token_endpoint
```

- Entra's app certificates are RSA.
- The JWT names the certificate by `x5t`, and its `aud` is the token endpoint.

## Keycloak: a ServiceAccount token

Keycloak's federated client authentication trusts the cluster's service-account issuer.

```yaml
exchangeToken: {enabled: true, audience: https://keycloak.example/realms/corp}   # the chart
config:
  issuers:
    - issuer: https://keycloak.example/realms/corp
      exchange:
        client_id: duckdb-secrets
        client_auth: file
        assertion_file: /var/run/tresor/idp-token/token
```

The chart mounts a projected ServiceAccount token with the audience the IdP expects. The kubelet rotates it,
and the service reads it at each request.

On Keycloak's side (see its documentation on federated client authentication for Kubernetes service
accounts):
- an identity provider trusts the cluster's service-account issuer;
- that issuer must be reachable from Keycloak, or its JWKS configured;
- the `duckdb-secrets` client authenticates with it, for the subject
  `system:serviceaccount:<namespace>:<serviceAccount>`.

## ZITADEL, on a stack with no Azure

ZITADEL suits a stack with no Azure at all: a European sovereign cloud (Hetzner, say), Kubernetes with no cloud
identity and no KMS.

**As the issuer of callers.** In the ZITADEL app:
- set the access token type to **JWT**: the default is opaque, and the service verifies JWTs only;
- enable *User roles inside Access Token*.

```yaml
issuers:
  - issuer: https://acme.zitadel.cloud
    audience: <the app's client id>
    roles_claim: urn:zitadel:iam:org:project:roles     # an object: its keys are the roles
```

**For token exchange** (ZITADEL 4.11 or later):
- The service's client is an OIDC app with the grant type *Token Exchange*. Use *Private Key JWT* and
  download the key file.
- The key file goes in a Kubernetes Secret, mounted for the service. Its `keyId` and `clientId` are read from
  it:

  ```yaml
  exchange: {client_auth: key_file, key_file: /etc/tresor-zitadel/key.json}
  ```

- **The audience can only be narrowed.** A downstream project must already be in the caller's token. The
  caller's login asks for it with the scope `urn:zitadel:iam:org:project:id:<project>:aud`: add it to the
  issuer's `scopes`, which tresor sends.
- **No refresh token by exchange.** When the token expires, the service exchanges again, as long as the
  delegation grant's subject token lives.
- **The key file is a static key**:
  - It is asymmetric, never sent, and revoked and replaced in ZITADEL. Rotate it there.
  - ZITADEL generates it, so a key of your own cannot be registered.
  - Where there is Azure after all, import it into Key Vault and use `keyvault`.
- **The chart** mounts the key file from a Secret through `extraVolumes` and `extraVolumeMounts`.
- **The service reads the key file at start.** After a rotation, update the Secret and restart the pods.

## Keys in Key Vault

- `keyvault` signs with the key's **current version**. Rotating it changes the key the IdP must know: register
  the new one first.
- The service reads the key's type at start. A vault that does not answer then stops the start, as for the
  KEK.
- Readiness signs a test assertion every 30 seconds per replica.
