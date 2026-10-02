# Spec 007: OpenBao and HashiCorp Vault

- **Status**: accepted
- **Date**: 2026-10-02
- **Author**: hugr lab

## Summary

**OpenBao** and **HashiCorp Vault** become the service's KMS and secret store where there is no cloud's. Both
speak the same API, and this spec uses "Vault" for either.
- **The KEK in Transit**: data keys wrapped by a Transit key, the root a Transit HMAC.
- **References** `ref+vault://<mount>/<path>#<field>` to KV v2, and `state.password_ref` from it.
- **The exchange's assertion** signed by a Transit key (spec 006's `client_auth`).
- **Logged in with no static secret**: the Kubernetes auth method, the JWT auth method (a projected token), or
  a token file a Vault Agent keeps.

It comes before AWS and GCP (the owner's order, 2026-10-02). It completes the stack with no cloud (spec 006's
Hetzner and the like): today that stack's KEK is a local key in a Kubernetes Secret, and its ZITADEL key a
file. With OpenBao, neither leaves the vault.

## Problem

- **The stack with no cloud** has no KMS. Its KEK is a static key in a Secret: whoever reads that Secret, and
  the store, reads every secret.
- **Organisations that run Vault** keep their credentials in KV already, and want DuckDB to read them there,
  as `ref+azkv` does for Key Vault.
- **ZITADEL's key file** for the exchange is a static key in a Secret. Transit can hold it (BYOK import) and
  sign with it.

## Design

### One client, `internal/vault`

- **A thin HTTP client** over the few endpoints needed. No SDK: the service needs a handful of calls, and an
  SDK links much more (spec 003 kept the binary lean the same way).
- **Configuration**:

  ```yaml
  vault:
    address: https://bao.example.eu:8200
    namespace: ""                   # a Vault or OpenBao namespace, when one is used
    ca_file: ""                     # a private CA; the system's otherwise
    auth:
      method: kubernetes            # kubernetes | jwt | token_file
      mount: kubernetes             # the auth method's mount
      role: tresor-server
      jwt_file: ""                  # jwt: the token to log in with (a projected ServiceAccount token)
      token_file: ""                # token_file: the token a Vault Agent writes
  ```

- **Rules**:
  - `https` unless the address is a loopback one.
  - A login's token is replaced by a new login at two thirds of its lease, not renewed. While a new login
    fails, the old token serves until its own end.
  - A 403 is checked with `lookup-self`: a dead token is replaced, while a live one (the policy's refusal)
    costs no login.
  - Redirects are never followed: they would carry the token and a data key elsewhere, http included.
  - A token file is read again when it changes.
  - Nothing logs a token.

### The KEK: `keys.kind: vault`

```yaml
keys: {kind: vault, mount: transit, key: tresor-kek}
```

- **The key** is an `aes256-gcm96` Transit key. The KEK never leaves Vault.
- **Wrap and unwrap**: `transit/encrypt/<key>` and `transit/decrypt/<key>`.
  - The KEK id is `vault:<mount>/<key>:v<N>`, with N the version the ciphertext names.
  - `Current` reads the key's `latest_version`, at most once a minute (as Key Vault's).
- **The key is checked** on every read of its version, and refused unless it is:
  - `aes256-gcm96` or `chacha20-poly1305`, not derived;
  - not exportable, and not backed up in plaintext: its HMAC keys would leave Vault;
  - `min_encryption_version` 0: anything else refuses the HMAC at older versions.
- **A replica learns of a rotation from its own wrap**: Transit wraps under the latest version. Otherwise a
  stale cache would make a new data key at every seal.
- **`ErrSealed` only for Transit's lasting answers about a value or a version**: a ciphertext that does not
  open, a version retired or never made. A key not found or a permission is a configuration (`503`).
- **The root (spec 003)** is `transit/hmac/<key>/sha2-256` of the fixed label at the KEK id's version.
  - Every Transit key carries an HMAC key per version, deterministic and never exported: only a holder of
    the right computes it.
  - `rewrap` and the data keys' tags work as for every KEK.
- **The policy the service needs**, on that one key: `encrypt`, `decrypt`, `hmac`, and `read` of the key.
- **Rotation**: `transit/keys/<key>/rotate`, then `tresor-server rewrap`. To retire the old versions, raise
  `min_decryption_version` once the rewrap has passed.

### References: `ref+vault://<mount>/<path>#<field>`

```yaml
material:
  vault:
    allow:
      - mount: secret
        prefixes: [duckdb/]          # paths under the mount
    cache_ttl: 0s
```

- **KV v2**: `GET <mount>/data/<path>`, and the field of `data.data`. The version read is logged; the value
  never is.
- **The rules of every reference source** (specs 002, 003):
  - a strict parse: no `..`, no query, no escape; the path's segments are KV's characters only;
  - the allowlist again at each read;
  - 503 when the value may come later, 500 when it will not (variables);
  - an administrator's only;
  - UTF-8 text only.
- **`state.password_ref: ref+vault://…`** reads the database's password, outside every allowlist (spec 003's
  rule).

### The exchange's assertion: `client_auth: vault`

```yaml
exchange: {client_id: …, client_auth: vault, key: transit/zitadel-app, kid: <the IdP's key id>}
```

- **Signing**: `transit/sign/<key>/sha2-256` with `prehashed: true`.
  - `pkcs1v15` for an RSA key (RS256);
  - `marshaling_algorithm: jws` for an ECDSA P-256 key (ES256).
- **ZITADEL's key** is imported into Transit (BYOK) and the file destroyed: the stack with no cloud then holds
  no static key of the service's own.
- **The key's type** is read at start: `rsa-2048`, `rsa-3072`, `rsa-4096` or `ecdsa-p256`; any other is refused.
- **The version is pinned** at start (`key_version`): the IdP knows one public key, named by `kid`, so a
  rotation takes effect at a restart, with the new `kid`. A signature of another version is refused.
- **One signature at start**: a missing right to sign, or a key that cannot sign, stops the start.
- **Tested** against OpenBao and Vault: keys made in Transit checked with their public keys, and an RSA key
  imported (wrapped by Transit's wrapping key, as `bao transit import` does) checked with the key held outside.

### Deployment

- **The chart**: `vault` in `config`, a projected token for the `jwt` method (the same mechanism as
  `exchangeToken`), `ca_file` through `extraVolumes`.
- **The docs**: a Vault page, covering the policies, the Kubernetes and JWT auth set-up, Transit, KV, and
  ZITADEL's key import.

## The PRs

1. **(a)** the client, its three logins, the KEK in Transit with its root (landed: tested against OpenBao 2.4.1
   and HashiCorp Vault 2.1.1 in CI);
2. **(b)** `ref+vault`, `state.password_ref` (landed);
3. **(c)** `client_auth: vault` (landed);
4. **(d)** the docs, the chart, and the stack with no cloud on kind: OpenBao with Kubernetes auth, the KEK
   in Transit, the Kubernetes store.

## Enforcement & security

- **Fail closed.**
  - A Vault that does not answer gives `503`.
  - A KEK version that is gone gives `ErrSealed`.
  - A login that fails leaves the service not ready (the `keys` check).
- **No static secret** with `kubernetes` or `jwt`. `token_file` holds a token a Vault Agent renews: the
  agent's own login is the platform's.
- **Least privilege**:
  - the service's Vault policy names its Transit key, its KV paths and its signing key;
  - the allowlist bounds what an administrator's reference can read within those.

## Testing

- **Unit tests**:
  - each endpoint against a fake Vault;
  - token renewal and the login again;
  - the parse;
  - the allowlist.
- **CI, against the real thing in docker**: OpenBao and HashiCorp Vault, both in dev mode.
  - The suite runs over each: the KEK (seal, open, rotate, rewrap, a forged data key refused), `ref+vault`,
    signing.
  - The login is by `jwt`, against a JWKS of the test's own, and by `token_file`.
- **kind**: OpenBao in the cluster, with the Kubernetes auth method.
  - The chart on the Kubernetes store, with the KEK in Transit;
  - checked through the protocol (`kind.sh`'s fixtures).
- **Conformance** on the Kubernetes store with the KEK in Transit: optional, if the kind run already covers
  it.

## Alternatives considered

- **An SDK** (`github.com/hashicorp/vault/api`, `github.com/openbao/openbao/api`): more than is needed, two
  near-identical ones to choose between, and licences to watch. One thin client serves both.
- **Transit's `datakey` endpoint** in place of the service's own data keys: the envelope stays one for every
  KEK.
- **Transit's convergent encryption for the root**: HMAC is what Transit offers for a deterministic,
  holder-only value.
- **AppRole**: its secret id is a static secret, which spec 001 avoids where the platform has an identity.
