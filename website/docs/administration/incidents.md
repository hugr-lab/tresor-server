---
title: Incidents
---

# Incidents

**Who**: the platform operator. The log says what failed; it names, never quotes a value.

## The service unready

`/readyz` is 503 when a check is `unavailable` or `not checked yet` (`degraded` is still ready). It names each
check's status; the error is in the log ([Operations](../operations.md#health)). The console's Service screen
shows the same.

| Check | Unavailable means | Act |
| --- | --- | --- |
| `state` | the store does not answer; on SQLite, this replica does not hold the lease; a SQL schema not current; on the Kubernetes store, the installation's mark does not verify (a wrong KEK or `state.instance`) | the database, its login ([credentials](credentials.md#the-databases-password)); the [lease](#the-sqlite-store-held); the KEK and instance a backup was taken with |
| `keys` | the KEK does not wrap and unwrap a throwaway key | [a KEK unreachable](#a-kek-unreachable) |
| `keys.previous[i]` | a previous KEK, or the operation its root needs (Transit's `hmac`, Key Vault's `sign`) | its rights; or finish the [move](kek.md#moving-to-another-kek) |
| `issuer <url>` | its discovery or signing keys never answered. Down after answering once: `degraded` | the IdP, the network, a private CA (`SSL_CERT_DIR`) |
| `exchange <url>` | `degraded` only: the service cannot make its client assertion | [the IdP's client](credentials.md#the-client-at-the-identity-provider-exchange) |

A replica that does not start at all names the setting or the right in its log: a configuration error, a KEK or a
Transit key that does not answer at start, the CRDs not served, no identity injected.

## A KEK unreachable

- **`503`**: the KEK does not answer (the vault, the network, the identity's token). Try later; a seal needs no
  vault while its data key is in memory (`keys.cache_ttl`), and Key Vault's last version read serves for an hour.
  Check the vault, the service's rights on the key, the identity.
- **`500 service_error`**: something does not open, and an operator must act:
  - a data key another KEK wrapped, or under a KEK no longer configured: put it back in `keys.previous`
    ([The KEK](kek.md#back));
  - a data key not authentic (its tag), or with no tag after an upgrade: `rewrap -tag-untagged`
    ([Upgrading](upgrading.md#authenticated-data-keys-spec-003));
  - a row under a deleted data key; a tampered value.

`tresor.kek.operations` by outcome shows which ([Observability](../observability.md#metrics)).

## Rows refused

A row (a SQL store with `state.mac: true`) or a resource (the Kubernetes store) whose MAC does not verify is
refused: a read fails (`500` to an administrator, `404` to anyone else on the Kubernetes store), a list leaves it
out, a delete passes. `tresor.state.left_out` counts them; the log names each.

- **Changed by hand** (`kubectl edit`, a write in the database): the store's own protection. Delete it, and have
  an administrator write it again.
- **From another installation**, or `state.instance` / the installation id changed: restore the right one
  ([Backup and restore](backup-restore.md)).
- **A SQL row with no MAC** (written by an older replica): `mac`, once every replica runs the new version
  ([Upgrading](upgrading.md#the-sql-stores-mac-spec-014)).
- **With `state.mac` off**, a row that does not verify is served, logged and counted.

## The SQLite store held

One replica serves; it holds a lease row, renewed every 5 seconds (15 seconds expiry). Another replica waits,
unready (`state`), and takes over when the first stops.

- A second replica waiting is by design: one serves.
- A command (`mac`, `reseal`) stops with "the SQLite database is held by a serving replica": stop the service,
  run it, start it ([Running a command](commands.md#sqlite)).
- A clean stop frees the lease at once; after a crash, it expires within 15 seconds.

## The IdP refuses the service's client

Reads of `token_exchange` secrets answer `503`; the log has an error, "the identity provider refused the
service's own client", with the issuer and the IdP's code (`invalid_client`, `unauthorized_client`) and
description. The audit's outcome is `error`. Nothing is stored in a delegation grant: fix the client (a secret
expired, a federated credential, the exchange permission) and the next read mints
([The service's own credentials](credentials.md)).

## Minted tokens refused

- **The user's session ended**: the IdP answers `invalid_grant` - the refresh token or the subject token is dead.
  The read is refused (`403`), and the refusal is kept in the delegation grant. A new session (a new login, a new
  delegation grant) mints again. Not an operator's fault.
- **A refusal for one secret** (`invalid_scope`, `invalid_target`, Keycloak's per-audience refusals): `403`, an
  administrator's fix in that secret or the IdP's client.
- **Entra's `AADSTS65001`**: consent missing for the downstream API
  ([Token exchange](../token-exchange.md#entra-on-behalf-of-a-federated-credential)).
