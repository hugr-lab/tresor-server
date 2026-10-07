# Spec 012: AWS and GCP - KMS as the KEK, their secret stores as sources, no static secret

- **Status**: accepted
- **Date**: 2026-10-06
- **Author**: hugr lab

## Summary

Phase 4 (spec 001): the service runs on AWS and on GCP as it runs on Azure. AWS KMS and Cloud KMS hold the KEK;
AWS Secrets Manager and GCP Secret Manager are reference sources (`ref+aws://`, `ref+gcp://`, named instances
from the start, spec 008); the service signs in to them, to its database and to its IdP's token endpoint with
the platform's identity (IRSA or EKS Pod Identity, GKE Workload Identity, an instance's or a VM's role), never a
static secret.

## Problem

On AWS and GCP today the KEK is a local key (a static secret in a Kubernetes Secret) or a Vault the installation
runs itself; references reach only Azure Key Vault, Kubernetes Secrets and Vault; a database password is static.
The organizations hugr serves keep their credentials in Secrets Manager or Secret Manager already.

## Design

### Identity

- **AWS**: the SDK's default chain - EKS Pod Identity, IRSA (a projected web identity token), an instance's or a
  task's role. `aws: {region: eu-central-1}`; no access key setting exists (static keys from the environment are
  refused at start - the legacy `AWS_ACCESS_KEY` too - as they would bypass the platform's identity), unless
  `aws.static_credentials: allow` says so - for development and tests (an emulator), logged as a warning at start.
- `aws.endpoint_url`: another endpoint for every AWS API the service calls (an emulator, a VPC endpoint), from
  configuration only: an `AWS_ENDPOINT_URL*` variable is refused at start.
- **GCP**: Application Default Credentials - GKE Workload Identity, a VM's service account, workload identity
  federation. A service account key or a person's login (from `GOOGLE_APPLICATION_CREDENTIALS` or gcloud's file)
  is refused at start, unless `gcp.static_credentials: allow` (tests).
- The chart: `serviceAccount.annotations` for IRSA (`eks.amazonaws.com/role-arn`) and GKE WI
  (`iam.gke.io/gcp-service-account`), as `workloadIdentity` does for AKS.

### The KEK

The envelope needs two things of a KEK (specs 002, 003): to wrap a data key, and a **root** only its holder can
compute, which authenticates the data keys (and the Kubernetes store's MACs). Vault's Transit key does both
(encrypt, hmac); Key Vault's RSA key both (wrap, sign). A KMS symmetric encryption key does not MAC, so each
cloud's KEK is **two keys**:

```yaml
keys:
  kind: awskms
  key: arn:aws:kms:eu-central-1:123456789012:key/…        # SYMMETRIC_DEFAULT: Encrypt, Decrypt
  mac_key: arn:aws:kms:eu-central-1:123456789012:key/…    # HMAC_256: GenerateMac
---
keys:
  kind: gcpkms
  key: projects/p/locations/europe-west3/keyRings/tresor/cryptoKeys/kek       # ENCRYPT_DECRYPT
  mac_key: projects/p/locations/europe-west3/keyRings/tresor/cryptoKeys/root/cryptoKeyVersions/1  # MAC (HMAC_SHA256): a version - a MAC key has no primary
```

- **Wrap**: KMS `Encrypt` with an encryption context (AWS) or additional authenticated data (GCP) binding the
  data key's purpose (`tresor-server/data-key/1`); `Unwrap`: `Decrypt` with the same.
- **Root**: KMS `GenerateMac` / `MacSign` over `tresor-server/root/1 ‖ kekID`, as the other KEKs' roots.
- **The KEK id** names both keys and their versions where the cloud exposes them:
  - AWS: `awskms:<key ARN>;mac:<mac key ARN>`. KMS rotates a symmetric key's material inside the same key (old
    material still decrypts), so the id does not change with it and no `rewrap` is needed; an HMAC key does not
    rotate. A move to other keys is spec 011's.
  - GCP: `gcpkms:<key>/cryptoKeyVersions/<n>;mac:<mac key>/cryptoKeyVersions/<m>`: the primary version wraps;
    a new primary is a new id, so data keys move with `rewrap` (as Vault's and Key Vault's versions).
- **Owns** (spec 011): its exact id - both ARNs (AWS); its key's name with any version (GCP).
- The service's role needs: AWS `kms:Encrypt`, `kms:Decrypt`, `kms:GenerateMac` on the two keys (the signer,
  `kms:Sign` and `kms:DescribeKey` on its key); GCP `cloudkms.cryptoKeyVersions.useToEncrypt`, `useToDecrypt`, `useToSign` (MAC) and
  `cloudkms.cryptoKeys.get` on the keys. The docs give a policy and a custom role.

### The sources

- **`ref+aws://<secret>[#<json field>][?version=<id>]`**: an AWS Secrets Manager secret by name, in the source's
  region and account; its string, or one field of a JSON secret. A version id pins one version; staging labels
  (`AWSPREVIOUS`) are not accepted.
- **`ref+gcp://<project>/<secret>[/<version>]`**: a GCP Secret Manager secret, `latest` by default.
- **Allowlists** as the other sources': AWS - `region`, `account` and name prefixes; GCP - projects and
  name prefixes. Nothing outside them is read.
- **Named instances** (spec 008): `material.sources[]` with `kind: aws` (another region or account, through an
  assumed role: `role_arn`, the only cross-account login) and `kind: gcp` (another allowlist and cache; the same
  identity - a project is in the reference).
- A binary secret (AWS `SecretBinary`) is refused: a reference is a VARCHAR value.

### The database

- `state.auth: aws` for PostgreSQL on RDS and Aurora: an IAM authentication token (15 minutes), made per new
  connection by the SDK's signer, with TLS required.
- `state.auth: gcp` for Cloud SQL for PostgreSQL: an IAM database user, the service account's OAuth token as the
  password (the Cloud SQL connector is not used: plain TLS to the instance's IP, its server CA from the config).
- SQL Server on AWS (RDS) has no IAM login: a password by reference (`ref+aws://`), as on other clouds.

### Token exchange without a client secret (spec 006)

- `client_auth: awskms` and `client_auth: gcpkms`: the client assertion (a JWT) signed by an asymmetric KMS key
  (RSA or ECDSA), as `keyvault` and `vault` do; `kid` is what the IdP knows the key by.

### The PRs

1. **(a) AWS**: `aws:` identity, `awskms` KEK, `ref+aws`, `state.auth: aws`, `client_auth: awskms`; tests
   against moto in CI (KMS with HMAC keys, Secrets Manager; Apache-2.0, no account needed); the chart's IRSA
   annotation.
2. **(b) GCP**: `gcp:` identity, `gcpkms` KEK, `ref+gcp`, `state.auth: gcp`, `client_auth: gcpkms`; tests with
   fakes of the two APIs (no emulator exists for Cloud KMS or Secret Manager); CRC32C checked on every call; the
   chart's GKE annotation.
3. **(c) Docs and live runs**: an AWS page (EKS, IRSA, RDS) and a GCP page (GKE, WI, Cloud SQL); one live run on
   each cloud, by hand, with the owner's agreement on the resources and their deletion afterwards.

## Enforcement & security

- **No static secret** for the service itself: static AWS keys and GCP key files are refused at start; the
  cross-account login is a role assumed with the platform's identity.
- **Fail closed**: a KMS that refuses or does not answer is an error (`503` when transient, `ErrSealed` when the
  ciphertext or the context does not match), never an empty value.
- **The root's key is not the wrapping key**: a role that may decrypt but not `GenerateMac` cannot authenticate a
  data key it planted; the docs say to grant the two to the service's role only.
- **References**: parsed strictly, the request built from parsed parts, never a URL from the text; allowlists
  before any call; values never logged, versions logged.
- **Region and endpoints**: from configuration only, never from a reference; a FIPS endpoint can be set.

## Testing

- Go: each KEK and source against a fake of its API (requests, contexts, errors mapped to `ErrSealed` / `503`);
  the root deterministic and bound to the KEK id; Owns; config validation (no static credentials, allowlists).
- CI: moto (an AWS emulator: KMS with symmetric, HMAC and signing keys, Secrets Manager) - through the service's
  own wiring: the awskms KEK on SQLite with its readiness, a move from a local KEK (spec 011) and `rewrap`,
  `ref+aws` as a string and a JSON field, the allowlist, signing with a KMS key. The image is pinned by digest
  (moto 5.1's GenerateMac fails). RDS IAM authentication: the token's shape, signed offline.
- Live, by hand, after the owner agrees: EKS with IRSA, KMS, Secrets Manager, RDS IAM auth; GKE with Workload
  Identity, Cloud KMS, Secret Manager, Cloud SQL IAM auth. Resources deleted afterwards.

## Alternatives considered

- **One KMS key, the root from a ciphertext**: a root must be deterministic; KMS ciphertexts are not. Rejected.
- **The root from the decrypted data key itself**: it would prove the data key decrypts, not that the service
  made it - anyone with `kms:Encrypt` (often wider than decrypt) could plant one. Rejected; spec 003's reason.
- **An asymmetric KMS key for both** (wrap with the public key, sign for the root): wrapping with a public key
  needs no permission at all, so the root carries everything; Key Vault does this because it must. On AWS and
  GCP a symmetric key is cheaper and its Encrypt is authenticated. Kept as a possible later option.
- **The Cloud SQL Go connector**: a dependency and a dialer for what TLS and an IAM token do. Rejected.

## Open questions

- ~~Whether AWS KMS HMAC keys are offered in every region~~: they are, in every region KMS is (AWS's KMS
  developer guide, "HMAC keys"); they do not rotate automatically, so the root is stable.
- The live runs: EKS and GKE clusters cost money while they run; a run of a few hours each, deleted the same day.

## Follow-ups

- AWS KMS multi-region keys for a service in several regions.
