# Spec 021: an AWS recipe - ECS on Fargate, RDS by IAM in private subnets, in Terraform

- **Status**: implemented
- **Date**: 2026-10-14
- **Author**: hugr lab

## Summary

The AWS counterpart of spec 020: `deploy/aws-ecs`, a Terraform module - the service on ECS Fargate behind an
Application Load Balancer (HTTPS, a certificate in ACM for a domain of the user's), its task role the only
identity (no static key), the KEK in two KMS keys (spec 012), references in Secrets Manager within an allowlist,
PostgreSQL on RDS by IAM authentication in private subnets with no public access, and one task definition the
commands run with `aws ecs run-task` (spec 019). The same structure and README as the GCP recipe.

## Problem

- **No recipe**: an AWS user wires two KMS keys and their grants, a task role, RDS IAM authentication and its
  database user, the RDS CA for `verify-full`, private networking and a load balancer by hand.
- **The network**: tasks in private subnets need the internet - the identity providers' discovery and signing
  keys, the image - so a NAT gateway; KMS, Secrets Manager, Logs and STS through it, or VPC endpoints besides.
- **The HTTPS address**: unlike Container Apps and Cloud Run, ECS gives none: a load balancer and a certificate
  for a domain the user controls.

## Design

### The module

`deploy/aws-ecs/` - `main.tf`, `variables.tf`, `outputs.tf`, `versions.tf`, `README.md`, `examples/`. Providers: `hashicorp/aws`, `hashicorp/http` (the RDS CA bundle); the AWS CLI where Terraform runs (the `db-init` task, as spec 020's job).

| Input | Default | |
| --- | --- | --- |
| `region` | `eu-central-1` | |
| `prefix` | `tresor` | every resource's name |
| `vpc_id`, `private_subnet_ids`, `public_subnet_ids` | (none: made) | an existing VPC; none - a VPC of the recipe's own, two AZs |
| `domain`, `certificate_arn` | (required: domain) | the service's `public_url`; a certificate in ACM (none: one made and DNS-validated in `route53_zone_id` - one of the two is required) |
| `route53_zone_id` | (none) | an alias record for the load balancer, and the certificate's validation |
| `vpc_endpoints` | `false` | interface endpoints for KMS, Secrets Manager, STS, Logs, ECR and an S3 gateway endpoint, beside the NAT |
| `image` | ghcr.io's | pulled through the NAT |
| `issuers`, `admins`, `actors` | | as the other recipes |
| `material_prefixes` | `[duckdb/]` | the Secrets Manager names `ref+aws` may read (at least one) |
| `desired_count` | 2 | |
| `db_instance_class` | `db.t4g.micro` | |
| `deletion_protection` | `true` | on the database and the load balancer |

### What it makes

- **The task role** `<prefix>-task`: no key. `kms:Encrypt`, `kms:Decrypt`, `kms:DescribeKey` on the KEK;
  `kms:GenerateMac` on the MAC key - the service's alone, by the key's policy (the account administers the key
  and cannot MAC with it); `secretsmanager:GetSecretValue` on the allowlisted ARNs
  (a prefix per pattern); `rds-db:connect` on the database user. The execution role pulls the image and writes
  logs.
- **KMS**: `kek` (SYMMETRIC_DEFAULT, rotation on - KMS keeps the key id: no `rewrap` needed), `root` (HMAC_256,
  not rotated) with a key policy granting `GenerateMac` to the task role only; deletion window 30 days.
- **RDS**: PostgreSQL 16, `iam_database_authentication_enabled`, `rds.force_ssl`, in the private subnets, **not
  publicly accessible**, a security group admitting only the service's; encrypted storage, backups. The DSN to the instance's endpoint with `sslmode=verify-full` and the RDS CA bundle, which no
  system trust store holds: Fargate mounts no file, so a non-essential init container writes the region's bundle
  (AWS's published one, public data, in its environment) to a shared ephemeral volume, and the service's container
  starts once it has (`dependsOn: SUCCESS`).
- **The database user and its ownership**: an IAM user in PostgreSQL is a role granted `rds_iam`; the master user
  (its password in Secrets Manager, RDS-managed: `manage_master_user_password`) creates it once - `CREATE ROLE <user> LOGIN; GRANT rds_iam TO <user>; GRANT <user> TO <master>; ALTER DATABASE tresor OWNER TO <user>;` (PostgreSQL 16: the master owns the database only through a role it is in) - in a one-time
  `db-init` task (a PostgreSQL client image), run by Terraform with `aws ecs run-task` and waited for. The master
  password stays RDS's, rotated by it; only db-init's own execution role reads it. The master remains an
  operator's break-glass login: it can write rows, not forge them - `state.mac: true` (spec 014) is set.
- **ECS**: a cluster, the service (Fargate, `desired_count`, private subnets, no public IP), the ALB (HTTPS 443 with
  the certificate, HTTP redirected; health check `/readyz`), CloudWatch logs.
- **Commands**: one task definition `<prefix>-command`, the same image, role, settings and network; a command is
  `aws ecs run-task --overrides` with its arguments (`reseal -retire`, `rewrap`, …) - the README gives each line.
- **Outputs**: the URL, the task role's ARN, the keys' ARNs, the command's task definition, the subnets and the
  security group to run it with.

### The docs

`website/docs/aws.md`: a **Deploy on ECS** section and the network done right (private subnets, no public RDS,
endpoints or NAT); `administration/commands.md`: `aws ecs run-task`.

### CI

`terraform fmt -check`, `validate` beside spec 020's. The live run (EKS for spec 012 with the chart, and this
recipe) at the end, with the owner's yes: an account and its credentials (the AWS CLI is not set up here yet).

### The live run (2026-10-14)

`scripts/dev/ecs_live.sh` in the owner's account, at `tresor.aws.hugr-lab.com` (a subdomain of `hugr-lab.com`
delegated from Cloudflare to a Route 53 zone): `apply` made 46 resources, the certificate validated in about two
minutes; the service ready (`state` - RDS by IAM over `verify-full` to the init container's CA, `keys` - KMS, the
Entra issuer); through the URL with the node app's token, a secret with a `ref+aws` resolved in Secrets Manager and a
variable; `mac`, `reseal -rotate -retire` and `rewrap` by `run-task`, each exit 0; `destroy` after. Passed the first
time.

## Enforcement & security

- No static key; the task role only. The MAC key's `GenerateMac` is the service's alone.
- No public address on the database; the load balancer is the only public endpoint; TLS everywhere, `verify-full`
  to RDS.
- The master password is RDS-managed (Secrets Manager), never in Terraform's state; the IAM user owns the
  database.
- Whoever may run tasks with the command's definition, pass the task role (`iam:PassRole`), or change the service
  acts as the service: the README says so.

## Testing

- CI: `fmt`, `validate`.
- Live (at the end): apply in an account of the owner's; the protocol through the URL; `ref+aws`; the commands
  by `run-task`; `destroy`.

## Alternatives considered

- **App Runner**: it throttles an idle instance's CPU; the service works in the background. Rejected.
- **CloudFormation or CDK**: AWS's own, but a second tool beside spec 020's Terraform. Rejected for one tool.
- **VPC endpoints instead of a NAT** (found writing it): the service must reach its identity providers on the
  internet, so a NAT (or a proxy) stays; endpoints are an option beside it.
- **A task definition per command**: `run-task` overrides the command; one definition is enough.

## Open questions

- ~~A domain for the live run~~: a subdomain of the owner's `hugr-lab.com` (Cloudflare) delegated to a Route 53
  zone by NS records, so the recipe validates its certificate and points the name at the load balancer by itself;
  a domain elsewhere works without delegation too - an issued certificate (`certificate_arn`) and the name pointed
  at `lb_dns_name` by hand (the owner, 2026-10-14).
