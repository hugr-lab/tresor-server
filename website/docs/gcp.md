---
title: GCP
---

# GCP

On GCP (spec 012) the service uses, each optional:

- **Cloud KMS for the KEK** (`keys.kind: gcpkms`);
- **Secret Manager for references** (`ref+gcp://`);
- **Cloud SQL IAM database authentication** to PostgreSQL (`state.auth: gcp`);
- **a Cloud KMS key to sign the exchange's assertion** (`client_auth: gcpkms`).

Every call is made with the platform's identity: no key of the service's own. The wiring is tested against fakes
of the two APIs (no emulator exists for Cloud KMS or Secret Manager).

## The identity

Application Default Credentials, as the deployment has them:

- **GKE Workload Identity**: the service's Kubernetes ServiceAccount bound to a Google service account (on the
  chart: `serviceAccount.annotations` with `iam.gke.io/gcp-service-account: tresor@<project>.iam.gserviceaccount.com`),
  or granted IAM roles directly as a Kubernetes principal.
- **A VM's service account** (Compute Engine, Cloud Run).
- **Workload identity federation** (an `external_account` credentials file: no key in it).

A service account key or a person's gcloud login is a static secret: refused at start; so is federation through
a program, or from static AWS keys. The clients call `googleapis.com` only: another universe, another metadata
server (`GCE_METADATA_HOST`) or a client certificate's signer program in the environment stops the start.
`gcp.static_credentials: allow` admits one for development and tests, with nothing else changed.

## The KEK: a key and a MAC version

```yaml
keys:
  kind: gcpkms
  key: projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/kek                           # ENCRYPT_DECRYPT
  mac_key: projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/root/cryptoKeyVersions/1  # MAC, HMAC_SHA256
```

- **`key`** wraps the data keys with its primary version (`Encrypt`, `Decrypt`, with additional authenticated
  data the service checks back). Every request and answer is checked by its CRC32C.
- **`mac_key`** is a MAC key's version: it gives the KEK's root, which authenticates every data key
  (`MacSign`). A MAC key has no primary version, so the version is named.
- **Rotation**: a new primary version of `key` is a new KEK id - new data keys are wrapped under it, and
  `tresor-server rewrap` moves the old ones; old versions still decrypt until disabled. The MAC version does not
  change by itself; a new one is [a move to another KEK](encryption.md#moving-to-another-kek).

The service account needs, on `key`, `roles/cloudkms.cryptoKeyEncrypterDecrypter` (and `cloudkms.cryptoKeys.get`,
in `roles/cloudkms.viewer`, to read the primary); on `mac_key`, `roles/cloudkms.signer` (`useToSign` covers
`MacSign`). Grant the MAC key to the service alone: who can wrap and MAC can plant a data key.

## References: Secret Manager

`ref+gcp://<project>/<secret>[/<version>]`

```sql
CREATE PERSISTENT SECRET lake IN corp (
    TYPE gcs,
    KEY_ID 'GOOG...',
    SECRET 'ref+gcp://corp-data/duckdb-lake-hmac',
    SCOPE 'gs://lake'
);
```

- `<project>` is the project's id (not its number: one project under two names would slip past an allowlist);
  `<secret>` the secret's name; `<version>` a number. With none, the
  latest version is read at each fetch: a new version reaches DuckDB at its next fetch.
- The payload must be UTF-8 text, and is checked by its CRC32C.

```yaml
material:
  gcp:
    allow:
      - project: corp-data
        prefixes: [duckdb-]      # none: every secret of the project
    cache_ttl: 0s                # at most 5m
```

The service account needs `roles/secretmanager.secretAccessor` on those secrets (or the project). A named source
(`kind: gcp`, [References](references.md#named-sources)) gives another allowlist and cache under its own scheme;
it reads with the same identity.

## The database: Cloud SQL IAM database authentication

```yaml
state:
  kind: postgres
  dsn: host=<instance DNS name> user=tresor@<project>.iam dbname=tresor sslmode=verify-full sslrootcert=/etc/cloudsql/server-ca.pem
  auth: gcp
```

- The service account's OAuth token (scope `sqlservice.login`) is the password, renewed by its token source.
- The instance has the flag `cloudsql.iam_authentication=on`; the user is the service account's email without
  `.gserviceaccount.com`, added to the instance as an IAM user; the account needs `roles/cloudsql.instanceUser`.
  (`roles/cloudsql.client` is for the connector and the Auth Proxy, not used here.)
- TLS with `verify-full` needs a server certificate naming the host: give the instance a DNS name (a
  Google-managed CA, `GOOGLE_MANAGED_CAS_CA`) and connect to it. The Cloud SQL connector is not used.

## Token exchange: the assertion signed in Cloud KMS

```yaml
issuers:
  - issuer: https://idp.example
    exchange: {client_id: tresor, client_auth: gcpkms, key: projects/…/cryptoKeys/idp/cryptoKeyVersions/1, kid: <the IdP's name for it>}
```

An asymmetric key's version (`RSA_SIGN_PKCS1_*_SHA256`: RS256; `EC_SIGN_P256_SHA256`: ES256) signs the client
assertion; the service account needs `roles/cloudkms.signer` on it (and `cloudkms.cryptoKeyVersions.get`). The
IdP is given the version's public key (`gcloud kms keys versions get-public-key`).
