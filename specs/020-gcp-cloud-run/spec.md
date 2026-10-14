# Spec 020: a GCP recipe - Cloud Run, Cloud SQL by Private Service Connect, in Terraform

- **Status**: accepted
- **Date**: 2026-10-14
- **Author**: hugr lab

## Summary

Azure has a recipe a user deploys and edits (`deploy/azure-container-apps`, Bicep); Kubernetes, GKE included, has
the chart. GCP's serverless path has nothing: the GCP page lists what to grant, and each user assembles it. This is
`deploy/gcp-cloud-run`, a Terraform module (OpenTofu works too; Google's Infrastructure Manager runs it with no
local install): the service on Cloud Run with an identity of its own and no key, the KEK in Cloud KMS, references
in Secret Manager, PostgreSQL in Cloud SQL by IAM authentication over **Private Service Connect** - no public
address - and a Cloud Run job per command (spec 019). The AWS recipe (ECS on Fargate) follows as spec 021, the
same way.

## Problem

- **No recipe**: a GCP user reads spec 012's page and wires a service account, two KMS keys, IAM bindings, Cloud
  SQL's IAM user and its database's ownership, a DNS name for `verify-full`, by hand.
- **The network is where it goes wrong**: Cloud SQL's quickest setup is a public IP with authorized networks; the
  GKE live run (2026-10-14) used one, open, for an hour. A recipe must make the right one the easy one.
- **The DNS name**: `verify-full` needs the instance's DNS name, which resolves only through a private zone of the
  user's own (the live run found it).

## Design

### The module

`deploy/gcp-cloud-run/` - `main.tf`, `variables.tf`, `outputs.tf`, `versions.tf`, a `README.md` (deploy, what each
variable does, for production), an `examples/` tfvars. Providers: `hashicorp/google` only.

| Input | Default | |
| --- | --- | --- |
| `project` | (required) | an existing project; the recipe enables the APIs it needs |
| `region` | `europe-west1` | |
| `prefix` | `tresor` | every resource's name |
| `network`, `subnetwork` | (none: made) | an existing VPC and subnet for the service's egress and the PSC endpoint; none - a minimal VPC of the recipe's own |
| `image` | the release's tag | a version, never `edge` |
| `issuers`, `admins`, `actors` | (required: issuers, admins) | as the Bicep recipe: YAML in `TRESOR_*` |
| `material_allow` | `[{project: <project>, prefixes: [duckdb-]}]` | `material.gcp.allow` |
| `min_instances`, `max_instances` | 1, 3 | |
| `database_tier` | `db-custom-1-3840` | `db-f1-micro` for a trial |
| `deletion_protection` | `true` | on the database and the KMS keys' destruction |

### What it makes

- **The service's account** (`<prefix>-svc`): no key. Its bindings, each on its own resource, never the project:
  `cloudkms.cryptoKeyEncrypterDecrypter` and `cloudkms.viewer` on the KEK, `cloudkms.signer` on the MAC key,
  `secretmanager.secretAccessor` on the allowlisted secrets' project (or the secrets the user lists),
  `cloudsql.instanceUser` and `cloudsql.client` scoped by condition to the instance.
- **Cloud KMS**: a key ring, `kek` (ENCRYPT_DECRYPT, a rotation period - `rewrap` moves the data keys), `root` (MAC,
  HMAC_SHA256: the root; not rotated). `prevent_destroy` on both.
- **Cloud SQL**: PostgreSQL 16, `cloudsql.iam_authentication=on`, a Google-managed CA (`GOOGLE_MANAGED_CAS_CA`: a
  DNS name in the certificate), `ssl_mode = ENCRYPTED_ONLY`, **no public IP**, **Private Service Connect** enabled
  for the project; a PSC endpoint (a forwarding rule on an internal address in the subnet); a **private DNS zone**
  for the instance's DNS name, its A record the endpoint. The IAM user for the service's account.
- **The database's ownership**: Cloud SQL's IAM user has no rights on a database it did not make, and only SQL
  gives them. A one-time Cloud Run job, `<prefix>-db-init`, runs `GRANT "<user>" TO postgres; ALTER DATABASE
  tresor OWNER TO "<user>";` as `postgres` through the PSC endpoint (`verify-ca` against the instance's CA), then
  sets `postgres` a new random password nobody keeps. The first password is Terraform's (`random_password`), in
  Secret Manager for the job only - and in the Terraform state, which the README says to keep as a secret; it is
  dead once the job ran. Terraform runs the job once (`terraform_data` with `local-exec`, re-run only when the
  instance is replaced).
- **Cloud Run** (`<prefix>`): the image, the service account, `TRESOR_*` from the inputs (as `serviceEnv` in
  Bicep), the DSN `host=<dns name> user=<svc>@<project>.iam dbname=tresor sslmode=verify-full
  sslrootcert=<the instance's CA>` (the CA from Secret Manager, mounted as a file), `state.auth: gcp`;
  **Direct VPC egress** to the subnet (private ranges only); CPU always allocated and `min_instances` ≥ 1 (the
  service purges, renews and checks in the background); startup and liveness probes on `/healthz`, `/readyz`;
  ingress all, the URL its `public_url` (a custom domain: a variable).
- **Cloud Run jobs**, one per command - `<prefix>-reseal` (`reseal -retire`), `-reseal-rotate`, `-rewrap`, `-refs`
  (`refs -resolve`), `-mac` - the same image, account, settings and egress; no retries, a timeout. Run:
  `gcloud run jobs execute <prefix>-reseal --region <region> --wait`.
- **Outputs**: the URL, the service account's email, the KEK's and the MAC key's names, the jobs' names.

### The docs

- `website/docs/gcp.md`: a **Deploy on Cloud Run** section (the recipe), and **the network for Cloud SQL done
  right**: Private Service Connect (or a private IP by Private Services Access), never a public IP with open
  authorized networks; the private DNS zone for `verify-full`; Direct VPC egress for Cloud Run, the cluster's VPC
  for GKE. The GKE section names the same for the chart.
- `website/docs/administration/commands.md`: the Cloud Run jobs beside the Container Apps ones.

### CI

`terraform fmt -check`, `terraform validate` (no cloud, no credentials), and `tflint` if it adds value, in a job
like the Bicep one. A live run by hand, with the owner's yes: a fresh project, `apply`, the protocol check
(scripts/dev), the jobs, `destroy`.

## Enforcement & security

- No key for the service: the recipe makes none, and the service refuses one.
- No public address on the database; logins are IAM tokens over TLS, `verify-full` to the name in its certificate.
- Each binding on its resource; the MAC key's signer role is the service's alone (who can wrap and MAC can plant a
  data key).
- Whoever may run the jobs, deploy a revision or act as the service's account (`iam.serviceAccountUser`) acts as
  the service: the README says so (spec 019).
- `prevent_destroy` and `deletion_protection` on what holds the material's keys and the data.

## Testing

- CI: `fmt`, `validate`.
- Live (with the owner's yes): a fresh project; `terraform apply`; the protocol check through the URL (a secret, a
  `ref+gcp`, a variable); the jobs (`mac`, `reseal -rotate -retire`, `rewrap`); readiness; `terraform destroy`
  (deletion protection off for the run).

## Alternatives considered

- **A gcloud script**: not idempotent, hard for a user to edit. Rejected.
- **Config Connector**: for a GKE user, who has the chart. Rejected.
- **A private IP by Private Services Access (VPC peering)**: right too, more moving parts (a reserved range, the
  peering). PSC by default; a variable may switch, later.
- **App Engine, Cloud Functions**: no always-on CPU for the background work. Rejected.

## Open questions

- ~~The database's ownership without a password~~: a one-time Cloud Run job with a password that dies with it
  (the owner, 2026-10-14).

## Follow-ups

- Spec 021: the AWS recipe - ECS on Fargate behind an ALB (ACM, a domain of the user's), RDS PostgreSQL by IAM in
  private subnets, two KMS keys, Secrets Manager, a task definition whose command `run-task` overrides; VPC
  endpoints by default, a NAT gateway as the option. Its live run with EKS at the end (spec 012).
