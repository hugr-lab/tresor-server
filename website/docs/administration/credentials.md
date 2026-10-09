---
title: The service's own credentials
---

# The service's own credentials

**When**: a credential the service logs in with expires or is rotated: its client at an identity provider, the
database password, the Vault login, the cloud identity.

**Who**: the platform operator, with the IdP's, the database's or the vault's administrator.

Where the platform has an identity, the service holds no static secret: nothing to rotate. The static secrets
that remain are listed in [Security](../security.md#static-secrets-that-remain).

## The client at the identity provider (`exchange`)

For `token_exchange` secrets the service logs in to the IdP as its own client
([Token exchange](../token-exchange.md)). What a rotation takes depends on `client_auth`:

| `client_auth` | Rotation |
| --- | --- |
| `secret` | The secret is read from `client_secret_env` at start: change it, then restart the replicas. |
| `azure` | Nothing: the identity's token is the assertion. The federated credential names the identity. |
| `file` | Nothing: the kubelet rotates the projected token; the service reads it at each request. |
| `keyvault` | The key's current version signs, and `x5t` (or `kid`) is read at start: a rotation in the vault signs with the new version under the old name, and the IdP refuses (`503`) until the configuration and the replicas follow. Without that window: a new key under a new name, registered at the IdP; then `key` and `x5t` changed and the replicas restarted; then the old key removed. |
| `key_file` | ZITADEL's key: a new key in ZITADEL, the Secret updated, the replicas restarted. |
| `vault` | The version is pinned at start: rotate the key, register its new public key at the IdP, change `kid`, restart - back to back (a replica that restarts in between signs the new version under the old `kid`). An imported key: a new key imported under a new name, then `key` and `kid`. |
| `awskms`, `gcpkms` | Not documented as a rotation: a new key (or version) is a configuration change of `key` and `kid`, its public key registered at the IdP first. |

### A client secret (`secret`)

1. Make the new secret at the IdP. Where the IdP keeps two at once, keep the old one until step 3.
2. Put the new one where `client_secret_env` reads it: on the chart, the Secret `env` takes it from; on Container
   Apps, the app's secret **and each job's** - every command loads the configuration, and one with no secret in
   `client_secret_env` does not start.
3. Restart: `kubectl -n tresor rollout restart deploy/<fullname>`; on Container Apps,
   `az containerapp revision restart` (a secret's change makes no revision).
4. Remove the old secret at the IdP.

### While the IdP refuses the client

A secret wrong or expired, a federated credential that does not match, an app not found or not allowed to
exchange (`invalid_client`, `unauthorized_client`): reads of `token_exchange` secrets answer `503`, and the log
has an error with the IdP's code and description (spec 017). Nothing is kept in a delegation grant: once fixed,
the next read mints. Readiness reports `exchange <issuer>` as degraded when the service cannot make its assertion;
the service stays ready. See [Incidents](incidents.md#the-idp-refuses-the-services-client).

## The database's password

- **`auth: entra`, `aws`, `gcp`**: a token for each connection, from the service's identity. Nothing to rotate.
- **`auth: password`**: `password_file` and `password_ref` are read again for each new connection: a rotation
  needs no restart. `password_env` is read from the process's environment: a restart.

Steps, `password_ref` or `password_file`:

1. Change the password in the database and at the reference (the Kubernetes Secret, the Key Vault secret, the
   Vault field, the Secrets Manager secret) together. Open connections keep working; new ones read the new
   password.
2. Check: readiness `state` stays `ok`, and the log has no login error. Connections live 30 minutes: by then
   every one has logged in with the new password.

Back: the old password at both. The reference itself (`state.password_ref`) is a configuration change; it must
stay outside every `material` allowlist ([References](../references.md#the-databases-password)).

## The Vault login

No static secret: a ServiceAccount token (`kubernetes`, `jwt`) or a Vault Agent's token (`token_file`). The
service logs in again at two thirds of its token's lease; when that fails, the old token serves until its own
end. A refusal (`403`) with a live token is the policy's, and costs no login. See [OpenBao and Vault](../vault.md#the-login).

## The cloud identity

- **Azure**: a managed identity (Container Apps) or workload identity (AKS): no secret. Workload identity needs
  the federated credential for the ServiceAccount (`system:serviceaccount:<ns>:<sa>`); renaming the
  ServiceAccount or the namespace needs a new one first ([Kubernetes](../kubernetes.md)).
- **AWS**: EKS Pod Identity, IRSA, an instance's or a task's role. Static keys are refused at start
  ([AWS](../aws.md#the-identity)).
- **GCP**: Workload Identity, a VM's service account, workload identity federation. Keys are refused at start
  ([GCP](../gcp.md#the-identity)).

## A local KEK

A static secret: a new one is a [move to another KEK](kek.md#moving-to-another-kek).

## Check

- Readiness: `state`, `keys`, `exchange <issuer>` are `ok` ([Incidents](incidents.md#the-service-unready)).
- A `token_exchange` secret reads (`mint` in the audit, `ok`).
- No `error` in the log naming the IdP's client, the database login or the Vault login.
