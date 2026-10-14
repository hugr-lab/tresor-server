# Spec 021: an AWS recipe - ECS on Fargate, RDS by IAM in private subnets, in Terraform

- **Status**: draft
- **Date**: 2026-10-14
- **Author**: hugr lab

## Summary

The AWS counterpart of spec 020: `deploy/aws-ecs`, a Terraform module - the service on ECS Fargate behind an
Application Load Balancer (HTTPS, a certificate in ACM for a domain of the user's), its task role the only
identity (no static key), the KEK in two KMS keys (spec 012), references in Secrets Manager within an allowlist,
PostgreSQL on RDS by IAM authentication in private subnets with no public access, and one task definition per
command run with `aws ecs run-task` (spec 019). The same structure and README as the GCP recipe.

## Problem

- **No recipe**: an AWS user wires two KMS keys and their grants, a task role, RDS IAM authentication and its
  database user, the RDS CA for `verify-full`, private networking and a load balancer by hand.
- **The network**: tasks in private subnets need KMS, Secrets Manager, ECR, CloudWatch Logs and STS - through a
  NAT gateway, or VPC endpoints.
- **The HTTPS address**: unlike Container Apps and Cloud Run, ECS gives none: a load balancer and a certificate
  for a domain the user controls.

## Design

### The module

`deploy/aws-ecs/` - `main.tf`, `variables.tf`, `outputs.tf`, `versions.tf`, `README.md`, `examples/`. Providers:
`hashicorp/aws`, `hashicorp/random`; the AWS CLI where Terraform runs (the `db-init` task, as spec 020's job).

| Input | Default | |
| --- | --- | --- |
| `region` | (the provider's) | |
| `prefix` | `tresor` | every resource's name |
| `vpc_id`, `private_subnet_ids`, `public_subnet_ids` | (none: made) | an existing VPC; none - a VPC of the recipe's own, two AZs |
| `domain`, `certificate_arn` | (required: domain) | the service's `public_url`; a certificate in ACM (none: one made and DNS-validated in `route53_zone_id`) |
| `route53_zone_id` | (none) | an alias record for the load balancer, and the certificate's validation |
| `egress` | `endpoints` | `endpoints`: interface endpoints for KMS, Secrets Manager, ECR (api, dkr), Logs, STS and an S3 gateway endpoint; `nat`: a NAT gateway instead |
| `image` | ghcr.io's, by an ECR pull-through cache | Fargate pulls from public registries too, but the cache keeps tasks off the internet with `endpoints` |
| `issuers`, `admins`, `actors`, `material_allow` | | as the other recipes |
| `desired_count` | 2 | |
| `db_instance_class` | `db.t4g.micro` | |
| `deletion_protection` | `true` | on the database and the load balancer |

### What it makes

- **The task role** `<prefix>-task`: no key. `kms:Encrypt`, `kms:Decrypt`, `kms:DescribeKey` on the KEK;
  `kms:GenerateMac` on the MAC key (the service's alone); `secretsmanager:GetSecretValue` on the allowlisted ARNs
  (a prefix per pattern); `rds-db:connect` on the database user. The execution role pulls the image and writes
  logs.
- **KMS**: `kek` (SYMMETRIC_DEFAULT, rotation on - KMS keeps the key id: no `rewrap` needed), `root` (HMAC_256,
  not rotated). Key policies naming the task role; deletion window 30 days.
- **RDS**: PostgreSQL 16, `iam_database_authentication_enabled`, `rds.force_ssl`, in the private subnets, **not
  publicly accessible**, a security group admitting only the service's; encrypted storage, backups. The DSN to the instance's endpoint with `sslmode=verify-full` and the RDS CA bundle, which no
  system trust store holds: Fargate mounts no secret as a file, so a non-essential init container writes the bundle
  (from an SSM parameter the recipe fills with AWS's published bundle) to a shared ephemeral volume, and the
  service's container starts once it has (`dependsOn: SUCCESS`).
- **The database user and its ownership**: an IAM user in PostgreSQL is a role granted `rds_iam`; the master user
  (its password in Secrets Manager, RDS-managed: `manage_master_user_password`) creates it once - `CREATE ROLE
  "<user>" LOGIN; GRANT rds_iam TO "<user>"; ALTER DATABASE tresor OWNER TO "<user>";` - in a one-time
  `db-init` task (a PostgreSQL client image), run by Terraform with `aws ecs run-task` and waited for. The master
  password stays RDS's, rotated by it; nobody reads it.
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
- **A NAT gateway by default**: simpler, ~$32 a month per AZ, and the tasks' traffic to AWS APIs leaves the VPC.
  An option, not the default.
- **A task definition per command**: `run-task` overrides the command; one definition is enough.

## Open questions

- A domain for the live run: the owner's Route 53 zone, or a certificate for a domain elsewhere (DNS validation by
  hand). To decide before the run.
