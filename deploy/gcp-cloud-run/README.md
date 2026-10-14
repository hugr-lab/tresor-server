# tresor-server on Cloud Run (Terraform)

A recipe (spec 020): the service on Cloud Run with an identity of its own and no key, the KEK in Cloud KMS,
references in Secret Manager, PostgreSQL in Cloud SQL by IAM authentication over **Private Service Connect** - the
database has no public address - and a Cloud Run job per command. Edit it to your needs; OpenTofu works too, and
Google's Infrastructure Manager runs it with no local install.

## What it makes

| | |
| --- | --- |
| **The service's account** `<prefix>-svc` | no key; each grant on its resource: encrypt/decrypt and viewer on the KEK, signer on the MAC key, Secret Manager reads within the allowlist (an IAM condition per prefix), Cloud SQL instance user |
| **Cloud KMS** `<prefix>` | `kek` (encrypt, rotated every 90 days - then the `<prefix>-rewrap` job), `root` (MAC, HMAC-SHA256: the KEK's root, not rotated) |
| **Cloud SQL** `<prefix>-pg` | PostgreSQL 16, IAM authentication, a Google-managed CA (a DNS name in its certificate), TLS only, **no public IP**, Private Service Connect; backups and point-in-time recovery |
| **The endpoint** | an internal address in the subnet to the instance, and a **private DNS zone** for the instance's name - the service connects with `verify-full` |
| **Cloud Run** `<prefix>` | the image, the account, Direct VPC egress (private ranges), CPU always allocated, at least one instance (the service works in the background), probes |
| **Jobs** | `<prefix>-reseal` (`reseal -retire`), `-reseal-rotate`, `-rewrap`, `-refs` (`refs -resolve`), `-mac`; and `-db-init`, run once by `apply` |
| **A VPC** | `<prefix>-vpc` and a subnet, unless `network` and `subnetwork` name yours |

## Deploy

Needs Terraform 1.5+ (or OpenTofu), and `gcloud` where it runs (`apply` runs the `db-init` job once). The project
exists; you have Owner on it (or the roles to make the above).

```sh
cp examples/trial.tfvars my.tfvars    # project, issuers, admins
terraform init
terraform apply -var-file my.tfvars
terraform output url
```

- **`issuers`, `admins`, `actors`**: as the Configuration page, YAML in a string - the same values the Bicep recipe
  takes.
- **`material_allow`**: where `ref+gcp` may read (projects and secret name prefixes); by default this project's
  `duckdb-*` secrets.
- **The database's ownership**: the service's IAM user cannot own a database it did not make; `db-init` runs one
  statement as `postgres` through the endpoint, then sets `postgres` a password nobody keeps. Its first password is
  Terraform's: it is in the state - **keep the state as a secret** (a GCS backend with access restricted) - and dead
  once the job has run.

## Run a command

```sh
gcloud run jobs execute tresor-reseal --region europe-west1 --wait
gcloud run jobs executions list --job tresor-reseal --region europe-west1
```

Whoever may execute the jobs, deploy a revision, or act as `<prefix>-svc` (`iam.serviceAccountUser`,
`iam.serviceAccountTokenCreator`) acts as the service: grant that to the platform's operators only. See the
Administration pages.

## For production

- **A custom domain** in front (a load balancer, or Cloud Run's domain mapping): set the service's `public_url` to
  it (`TRESOR_PUBLIC_URL` in `local.env`).
- **Your network**: `network` and `subnetwork` - the subnet the service egresses from and the endpoint lives in.
- **The database**: `database_tier`, `availability_type = "REGIONAL"` in `main.tf` for a standby; deletion
  protection stays on.
- **Keep the KMS keys**: without them the database's material never opens. A destroy schedules the key versions'
  destruction (24 hours by default); restore them within it if a destroy was a mistake.
- **The image**: a version (`image`), never `edge`.
- Nothing here gives the database a public address: keep it so. Never add authorized networks.

## Destroy (a trial)

`deletion_protection = false`, `apply`, then `terraform destroy`. The KMS key ring remains (Cloud KMS never deletes
one); its keys' versions are destroyed after the delay.
