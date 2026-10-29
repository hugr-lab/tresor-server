# tresor-server on ECS Fargate (Terraform)

A recipe (spec 021): the service on ECS Fargate behind an HTTPS load balancer, its task role the only identity (no
key), the KEK in two KMS keys, references in Secrets Manager, PostgreSQL on RDS by IAM authentication in private
subnets with no public access, and a task definition the commands run with. Edit it to your needs; OpenTofu works
too.

## What it makes

| | |
| --- | --- |
| **The task role** `<prefix>-task-<region>` | no key: `kms:Encrypt`/`Decrypt`/`DescribeKey` on the KEK, `kms:GenerateMac` on the MAC key (the service's alone), `secretsmanager:GetSecretValue` on `material_prefixes`, `rds-db:connect` on its database user |
| **KMS** | `<prefix>-kek` (symmetric, rotated yearly by KMS - its id stays, no `rewrap`), `<prefix>-root` (HMAC_256: the KEK's root, not rotated; its key policy lets the task role alone MAC); a 30-day deletion window |
| **RDS** `<prefix>-pg` | PostgreSQL 16, IAM authentication, `rds.force_ssl`, private subnets, **not publicly accessible**, encrypted, backups; the master password kept and rotated by RDS in Secrets Manager - never in Terraform's state |
| **The database's user** | `<prefix>_svc`, granted `rds_iam`, owning the database `tresor` - made once by the `db-init` task `apply` runs, with an execution role of its own (the only one reading the master password); `state.mac: true` - every row authenticated |
| **ECS** | a cluster, the service (Fargate, private subnets, no public IP), an init container writing the RDS CA (no trust store holds it) to a volume the service reads for `verify-full` |
| **HTTPS** | an Application Load Balancer (TLS 1.2/1.3, HTTP redirected), an ACM certificate validated in `route53_zone_id`, an alias for `domain` |
| **The commands** | a task definition `<prefix>-command`, run with `aws ecs run-task` (below) |
| **A VPC** | two AZs, public and private subnets, one NAT gateway - unless `vpc_id` names yours; VPC endpoints with `vpc_endpoints` |

## Deploy

Needs Terraform 1.5+ (or OpenTofu) and the AWS CLI where it runs (`apply` runs `db-init` once), credentials for an
account (no static key for the service; yours: SSO or `aws login`).

```sh
cp examples/trial.tfvars my.tfvars    # domain, route53_zone_id, issuers, admins
terraform init
terraform apply -var-file my.tfvars
terraform output url
```

- **`domain`** is the service's `public_url`. With **`route53_zone_id`** the recipe validates the certificate and
  points the name at the load balancer. A domain elsewhere (Cloudflare, say): delegate a subdomain to a Route 53
  zone by NS records once - or give `certificate_arn` (an issued certificate) and point the name at `lb_dns_name`
  by hand.
- **`prefix`** (`tresor`): every resource's name - lower-case letters, digits and dashes, a letter first, no dash
  last or doubled, 15 characters at most.
- **`issuers`, `admins`, `actors`**: as the Configuration page, YAML in a string - the same values the other
  recipes take.
- **`material_prefixes`** (`duckdb/`): the Secrets Manager names `ref+aws` may read in this account and region -
  at least one, none empty.

## Run a command

```sh
aws ecs run-task --region <region> --cluster tresor --launch-type FARGATE --task-definition tresor-command \
  --network-configuration "awsvpcConfiguration={subnets=[<private subnets>],securityGroups=[<task_security_group>],assignPublicIp=DISABLED}" \
  --overrides '{"containerOverrides":[{"name":"tresor","command":["reseal","-retire"]}]}'
```

The command is the binary's arguments: `["reseal","-retire"]`, `["reseal","-rotate","-retire"]`, `["rewrap"]`,
`["refs","-resolve"]`, `["mac"]`. Its log is in CloudWatch Logs, `/ecs/<prefix>`. Whoever may run tasks with
this definition, pass the task role (`iam:PassRole`), or change the service acts as the service: grant that to the
platform's operators only (the Administration pages).

## The network

- The tasks and the database live in private subnets; the load balancer is the only public endpoint.
- **A NAT gateway is needed** whatever else: the service reaches its identity providers (discovery, signing keys)
  and pulls its image on the internet. `vpc_endpoints = true` keeps the traffic to KMS, Secrets Manager and Logs
  inside the VPC besides.
- One NAT gateway, in one AZ: a trial's. For production, one per AZ (edit `main.tf`), or your own VPC.

## For production

- `desired_count` ≥ 2, `db_instance_class` bigger, `multi_az = true` on the database (in `main.tf`).
- Deletion protection stays on (the database, the load balancer).
- **The master user** stays an operator's break-glass login (its password RDS's, in Secrets Manager): who reads
  that secret can write the database's rows - not forge them (`state.mac`). Keep `secretsmanager:GetSecretValue`
  on it to the few.
- `apply` waits for the service to be healthy, and rolls a failed deployment back.
- **Keep the KMS keys**: without them the database's material never opens. A destroy schedules their deletion
  (30 days); cancel it (`aws kms cancel-key-deletion`) if it was a mistake.
- The image: a version (`image`, `ghcr.io/hugr-lab/tresor-server:v0.8.2` by default), never `edge`.
- Nothing here makes the database public: keep it so.

## Destroy (a trial)

`deletion_protection = false`, `apply`, then `terraform destroy`. The KMS keys are scheduled for deletion (30
days); the CloudWatch log group goes.
