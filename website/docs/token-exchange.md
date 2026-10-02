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
      client_auth: secret          # secret | azure | file | keyvault | key_file | vault
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
| `vault` | a JWT it signs with `key` (`<mount>/<key>`) in Transit, OpenBao's or Vault's (RS256 or ES256), as `kid` | ZITADEL's key imported; any IdP with `private_key_jwt`, with OpenBao or Vault |

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
    audience: "<the project's id>"                                  # a token's aud is the project
    roles_claim: "urn:zitadel:iam:org:project:<the project's id>:roles"   # an object: its keys are the roles
```

- The caller asks for the project's audience and its roles with the scopes
  `urn:zitadel:iam:org:project:id:<project>:aud` and `urn:zitadel:iam:org:projects:roles`.
- ZITADEL names the roles in a claim of the project's own. `urn:zitadel:iam:org:project:roles` is there
  only for some flows, so use the project's.

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
- **No refresh token by exchange.** ZITADEL answers `Errors.TokenExchange.Token.TypeNotSupported`. The
  service then asks for an access token only, and exchanges again when it expires, as long as the delegation
  grant's subject token lives.
- **The key file is a static key**:
  - It is asymmetric, never sent, and revoked and replaced in ZITADEL. Rotate it there.
  - ZITADEL generates it, so a key of your own cannot be registered.
  - Where there is OpenBao or Vault, import it into Transit and use `vault` (below): no key file remains.
  - Where there is Azure after all, import it into Key Vault and use `keyvault`.
- **The chart** mounts the key file from a Secret through `extraVolumes` and `extraVolumeMounts`.
- **The service reads the key file at start.** After a rotation, update the Secret and restart the pods.

### A stack with no Azure

The chart on any Kubernetes (Hetzner, say). It has the Kubernetes store, a local KEK from a Secret, ZITADEL as
the issuer and ZITADEL's key file for the exchange: nothing of a cloud identity, no KMS.

```yaml
localKEK: {secretName: tresor-kek}                 # 32 random bytes, base64
extraVolumes: [{name: zitadel, secret: {secretName: tresor-zitadel-key}}]
extraVolumeMounts: [{name: zitadel, mountPath: /etc/tresor-zitadel, readOnly: true}]
config:
  public_url: https://tresor.example.eu
  state: {kind: kubernetes}
  issuers:
    - issuer: https://auth.example.eu
      audience: "<project id>"
      client_id: "<the login app's client id>"     # people log in with it (tresor's human flows)
      scopes: [openid, "urn:zitadel:iam:org:project:id:<project id>:aud",
               "urn:zitadel:iam:org:project:id:<downstream project id>:aud", "urn:zitadel:iam:org:projects:roles"]
      roles_claim: "urn:zitadel:iam:org:project:<project id>:roles"
      exchange: {client_auth: key_file, key_file: /etc/tresor-zitadel/key.json}
  policy: {admins: [role:secrets_admin]}
```

- The `scopes` are what tresor asks for at a login: the project's audience, every downstream project a
  `token_exchange` secret names, and the roles. Without them a caller's token has neither the audience nor
  the roles.
- The key file's Secret: `kubectl create secret generic tresor-zitadel-key --from-file=key.json=<the file>`.

`scripts/ci/zitadel.sh` checks this in CI, against ZITADEL in docker:
- roles from ZITADEL's object;
- a token minted by exchange, with the service logged in by the key file;
- ZITADEL's refusal of a refresh, read as such.

### ZITADEL's key in Transit

Where OpenBao or HashiCorp Vault runs, ZITADEL's key goes into Transit (BYOK) and the file is destroyed. The
service then signs in Vault with no key of its own.

1. Import the key (the key file's `key` field, PKCS#1 PEM, as PKCS#8 DER in base64):

   ```sh
   jq -r .key key.json | openssl pkcs8 -topk8 -nocrypt -outform DER | base64 | tr -d '\n' > key.b64
   bao transit import transit/keys/zitadel-app @key.b64 type=rsa-2048   # vault transit import, the same
   shred -u key.json key.b64
   ```

2. Let the service's Vault policy sign with it:

   ```hcl
   path "transit/keys/zitadel-app"          { capabilities = ["read"] }
   path "transit/sign/zitadel-app/sha2-256" { capabilities = ["update"] }
   ```

3. Configure the exchange with the key file's `clientId` and `keyId`:

   ```yaml
   vault: {address: https://bao.example.eu:8200, auth: {method: kubernetes, role: tresor}}
   issuers:
     - issuer: https://auth.example.eu
       exchange: {client_id: "<clientId>", client_auth: vault, key: transit/zitadel-app, kid: "<keyId>"}
   ```

- An imported key is not exportable, and cannot be rotated in Transit. Rotate it in ZITADEL: a new key,
  imported under a new name, then `key` and `kid` changed.
- See [`vault` in the configuration](configuration.md#vault) for the login.

## Keys in Transit

- `vault` signs with the key's **latest version**: an RSA key with PKCS#1 v1.5 (RS256), an ECDSA P-256 key in
  JWS form (ES256). Other types are refused at start.
- A key made in Transit (not imported) is registered at the IdP by its public key: `bao read transit/keys/<key>`.
  Rotating it changes that key: register the new one, then change `kid`.
- The service reads the key's type at start. A Vault that does not answer then stops the start, as for the KEK.

## Keys in Key Vault

- `keyvault` signs with the key's **current version**. Rotating it changes the key the IdP must know: register
  the new one first.
- The service reads the key's type at start. A vault that does not answer then stops the start, as for the
  KEK.
- Readiness signs a test assertion every 30 seconds per replica.
