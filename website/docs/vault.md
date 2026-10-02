---
title: OpenBao and Vault
---

# OpenBao and HashiCorp Vault

The service uses OpenBao or HashiCorp Vault (spec 007) for three things, each optional:

- **the KEK** in Transit (`keys.kind: vault`), see [Encryption](encryption.md#vault-openbao-or-hashicorp-vault-transit);
- **references** to KV v2 (`ref+vault://`), see [References](references.md#openbao-and-hashicorp-vault-kv-v2);
- **the exchange's assertion** signed in Transit (`client_auth: vault`), see
  [Token exchange](token-exchange.md#zitadels-key-in-transit).

The same API serves both. CI tests against OpenBao 2.4 and Vault 2.1.

Together with the Kubernetes store and ZITADEL, this is a stack with no cloud at all: no static secret of the
service's own, no key in a file.

## The login

The service logs in with no static secret:

| `vault.auth.method` | The token it logs in with | Set-up in Vault |
| --- | --- | --- |
| `kubernetes` | a ServiceAccount token: the chart's projected one (`vaultToken`), or the pod's own | the Kubernetes auth method |
| `jwt` | a projected ServiceAccount token (`jwt_file`) | the JWT auth method, trusting the cluster's issuer |
| `token_file` | a token a Vault Agent writes and renews | the Agent's own login |

- `kubernetes` suits Vault in the cluster, or one that can reach the cluster's API (it asks the API to review
  the token).
- `jwt` suits a Vault outside, which checks the token against the cluster's OIDC issuer and never calls the
  cluster.

### Kubernetes auth

```sh
bao auth enable kubernetes
bao write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc
bao write auth/kubernetes/role/tresor \
  bound_service_account_names=tresor-tresor-server bound_service_account_namespaces=tresor \
  audience=vault token_policies=tresor token_ttl=1h token_type=batch
```

- With Vault in the cluster, its own ServiceAccount reviews the tokens: bind it to `system:auth-delegator`.
- `audience=vault` is the chart's `vaultToken.audience`. The projected token is then good for Vault only.

### JWT auth

```sh
bao auth enable jwt
bao write auth/jwt/config oidc_discovery_url=https://<the cluster's issuer>
bao write auth/jwt/role/tresor role_type=jwt user_claim=sub \
  bound_audiences=vault bound_subject=system:serviceaccount:tresor:tresor-tresor-server \
  token_policies=tresor token_ttl=1h token_type=batch
```

## The policy

One policy, naming only what the service uses:

```hcl
# the KEK
path "transit/keys/tresor-kek"           { capabilities = ["read"] }
path "transit/encrypt/tresor-kek"        { capabilities = ["update"] }
path "transit/decrypt/tresor-kek"        { capabilities = ["update"] }
path "transit/hmac/tresor-kek/sha2-256"  { capabilities = ["update"] }
# ref+vault, within material.vault.allow
path "secret/data/duckdb/*"              { capabilities = ["read"] }
# client_auth: vault
path "transit/keys/zitadel-app"          { capabilities = ["read"] }
path "transit/sign/zitadel-app/sha2-256" { capabilities = ["update"] }
```

- Give `hmac` on the KEK to the service alone: whoever holds it computes the root.
- Admins write `ref+vault` references; the service reads them. Keep `read` under the prefixes the allowlist
  names.

## The chart

```yaml
vaultToken: {enabled: true, audience: vault}     # a projected token at /var/run/tresor/vault-token/token
env: [{name: SSL_CERT_DIR, value: /etc/tresor-ca}]
extraVolumes: [{name: ca, configMap: {name: vault-ca}}]
extraVolumeMounts: [{name: ca, mountPath: /etc/tresor-ca, readOnly: true}]
config:
  state: {kind: kubernetes}
  keys: {kind: vault, key: tresor-kek}
  vault:
    address: https://bao.bao.svc:8200
    ca_file: /etc/tresor-ca/ca.crt               # Vault's private CA
    auth: {method: kubernetes, role: tresor}     # jwt_file set by the chart (vaultToken)
  material:
    vault: {allow: [{mount: secret, prefixes: [duckdb/]}]}
```

- `vaultToken` mounts a projected ServiceAccount token, bound to `audience`, and sets `vault.auth.jwt_file` to
  it. `jwt` needs it (or a `jwt_file` of your own).
- With `kubernetes` and no `vaultToken`, the pod's own ServiceAccount token is mounted. It is good for the
  Kubernetes API too: prefer `vaultToken`.
- `ca_file` is Vault's alone. `SSL_CERT_DIR` is needed only when the issuer has a private CA too.

`scripts/ci/kind.sh` checks this in CI: OpenBao in the cluster with Kubernetes auth and the projected token,
the KEK in Transit, a `ref+vault` reference read through the protocol, on the Kubernetes store.

## Failures

- **Fail closed.** A Vault that does not answer gives `503`, never an empty value.
- A data key Transit says is not its own (a retired version, a ciphertext that does not open) is sealed.
- A 403 with a live token is the policy's refusal: it costs no new login.
