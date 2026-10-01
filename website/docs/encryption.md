---
title: Encryption
---

# Encryption

A secret's material is sealed before it reaches the state store: envelope encryption.

```mermaid
flowchart LR
  params["a secret's params"] -- "AES-256-GCM" --> sealed["sealed params (in the store)"]
  dek["data key"] -. "seals" .-> sealed
  kek["KEK (Key Vault, or local)"] -- "wraps" --> wrapped["wrapped data key (in the store)"]
  dek -.-> wrapped
```

- **A secret's params** are one JSON document, sealed with AES-256-GCM under a data key.
- **The AAD** names the row, the secret's name and its version. A sealed value copied to another secret,
  another version, or kept from a dropped secret of the same name does not open.
- **A data key** is random, wrapped by the KEK, and stored wrapped. Unwrapped ones stay in memory for
  `keys.cache_ttl` (5 minutes), never written or logged.
- **A delegation grant's tokens** (the user's token, the tokens minted for them) are sealed the same way,
  bound to the grant.
- **A data key is authenticated**: a tag under the KEK's root (below). One planted by whoever could write
  the store is refused.
- **What does not open is an error**, never an empty value: a tampered value, a data key another KEK
  wrapped or one that is not authentic (`500 service_error`); a KEK that does not answer (`503`).

## The root

An RSA KEK wraps with its **public** key: anyone who has it can make a data key that unwraps, and seal
material of their choice under it. So a data key that unwraps proves nothing. The service derives a
**root** that only the KEK's holder can compute, and tags every data key with it:

| KEK | The root |
| --- | --- |
| Key Vault RSA | a deterministic signature (RS256) of a fixed label, made in the vault |
| Managed HSM AES | a deterministic wrap (A256KW) of a fixed label |
| local | HMAC-SHA256 of a fixed label under the key |

- The root is never stored; it stays in memory for `keys.cache_ttl`, as the data keys do.
- A data key's tag is an HMAC under the root over its id, its KEK id and its wrapped bytes.
- A data key whose tag does not match is refused, on every store.
- **Upgrading from a version before this**: its data keys have no tag and are refused. Run
  `tresor-server rewrap` once: it tags them - you vouch for the store as it is. It never tags a data key
  whose tag does not match.

## The KEK

### `local`

```yaml
keys: {kind: local, key_env: TRESOR_KEK}   # or key_file: /run/secrets/kek
```

32 bytes, base64 (`openssl rand -base64 32`). Data keys are wrapped with AES key wrap (RFC 3394). For
development, tests and small installs: the key is a static secret.

### `azurekeyvault`

```yaml
keys: {kind: azurekeyvault, key: https://corp-kv.vault.azure.net/keys/tresor-kek}
azure: {identity: managed}
```

- A key in Azure Key Vault or Managed HSM. The KEK never leaves it: the service asks it to wrap and unwrap.
- `RSA-OAEP-256` for an RSA key (either service); `A256KW` for an AES key on Managed HSM.
- The service's identity needs get, wrap, unwrap and **sign** on the key - sign makes the root. No
  built-in role gives exactly these four: the recipes make a custom role, on the one key. On Managed HSM
  (an AES key), *Managed HSM Crypto Service Encryption User* is enough: the root is a wrap.
- The vault on the RBAC permission model, with purge protection: the material depends on the key.
- The key is named **without a version**. New data keys are wrapped under its current version; each data
  key records the version it was wrapped under.
- The current version is read at most once a minute. While the vault does not answer, the last one read
  serves for up to an hour: a seal needs no vault when its data key is in memory.

## Rotation

1. **Rotate the KEK in the vault** (by hand, or a rotation policy). The service sees the new version within
   a minute and makes a new data key for new values. Old values still open: their data keys name the old
   version.
2. **Rewrap**, to retire the old versions:

   ```bash
   tresor-server rewrap -config server.yaml
   ```

   Every data key is unwrapped under its old version and wrapped under the current one, compare-and-set.
   No sealed value is touched. It runs next to the service. It goes on past a data key it cannot rewrap,
   names each, and exits non-zero.
3. **Retire the old versions** in the vault once `rewrap` has passed.

Data keys also rotate by age: one older than `keys.data_key_max_age` (30 days) is replaced for new values.
