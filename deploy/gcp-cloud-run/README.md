# tresor-server on Cloud Run (Terraform)

A recipe (spec 020): the service on Cloud Run with an identity of its own and no key, the KEK in Cloud KMS,
references in Secret Manager, PostgreSQL in Cloud SQL by IAM authentication over **Private Service Connect** - the
database has no public address - and a Cloud Run job per command. Edit it to your needs; OpenTofu works too.

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
| **The image** | Cloud Run pulls from Artifact Registry or Docker Hub only: `<prefix>-ghcr`, a remote repository of `ghcr.io`, serves tresor-server's image (`image_tag`); or `image` names one of your own |

## Deploy

Needs Terraform 1.5+ (or OpenTofu), and `gcloud` where it runs (`apply` runs the `db-init` job once). The project
exists; you have Owner on it (or the roles to make the above).

```sh
cp examples/trial.tfvars my.tfvars    # project, issuers, admins
terraform init
terraform apply -var-file my.tfvars
terraform output url
```

- **`prefix`** (`tresor`): every resource's name - lower-case letters, digits and dashes, a letter first, no dash
  last or doubled, 15 characters at most.
- **`issuers`, `admins`, `actors`**: as the Configuration page, YAML in a string - the same values the Bicep recipe
  takes.
- **`material_allow`**: where `ref+gcp` may read (projects and secret name prefixes); by default this project's
  `duckdb-*` secrets.
- **The database's ownership**: the service's IAM user cannot own a database it did not make; `db-init` runs one
  statement as `postgres` through the endpoint, then sets `postgres` a password nobody keeps (`apply` retries it
  while its grants reach Secret Manager). Its first password is Terraform's: it is in the state - **keep the state
  as a secret** (a GCS backend with access restricted) - and dead once the job has run; its secret version is
  disabled then.
- **The CA**: `sslrootcert` holds the instance's current CA. When Cloud SQL announces a new one, `apply` again
  before it takes over (the GCP page).

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
- **Your network**: `network` and `subnetwork` - the subnet the service egresses from and the endpoint lives in. A
  Shared VPC: the Cloud Run service agent needs `roles/compute.networkUser` on the host project's subnet.
- **The database**: `database_tier`, `availability_type = "REGIONAL"` in `main.tf` for a standby; deletion
  protection stays on.
- **Keep the KMS keys**: without them the database's material never opens. A destroy schedules the key versions'
  destruction (30 days by default); restore them within it if a destroy was a mistake.
- **The image**: a version (`image_tag`, `v0.8.0` by default), never `edge`; `image` only for an image in a registry
  of your own (Artifact Registry or Docker Hub).
- Nothing here gives the database a public address: keep it so. Never add authorized networks.

## Destroy (a trial)

`deletion_protection = false`, `apply`, then `terraform destroy`. The database and its users are abandoned, not
dropped: they go with the instance.

- The subnet outlives the service for a while: Cloud Run's Direct VPC egress holds addresses in it, which Google
  releases some time after the service is gone - `destroy` stops on the subnet; run it again later (or delete the
  project).

- The KMS key ring and its keys remain (Cloud KMS never deletes one); their versions are destroyed after the delay.
- So another trial in the same project takes another `prefix` (the key ring's and the keys' names exist), and a
  Cloud SQL instance's name is not free again for about a week.
