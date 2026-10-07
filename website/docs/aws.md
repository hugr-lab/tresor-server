---
title: AWS
---

# AWS

On AWS (spec 012) the service uses, each optional:

- **AWS KMS for the KEK** (`keys.kind: awskms`);
- **Secrets Manager for references** (`ref+aws://`);
- **RDS IAM authentication** to PostgreSQL on RDS or Aurora (`state.auth: aws`);
- **a KMS key to sign the exchange's assertion** (`client_auth: awskms`).

Every call is made with the platform's identity: no static key of the service's own. CI tests the service's
wiring against moto (an AWS emulator).

## The identity

```yaml
aws:
  region: eu-central-1
```

The SDK's default chain, whichever of these the deployment has (the SDK tries IRSA's web identity first):

- **EKS Pod Identity**: an association between the service's ServiceAccount and an IAM role; nothing in the
  chart.
- **IRSA**: the ServiceAccount annotated with the role, the role trusting the cluster's OIDC provider. On the
  chart: `serviceAccount.annotations` with `eks.amazonaws.com/role-arn: arn:aws:iam::<account>:role/tresor`.
- **An instance's or a task's role** (EC2, ECS).

Static keys from the environment (`AWS_ACCESS_KEY_ID`, and the SDK's legacy `AWS_ACCESS_KEY`) are refused at
start: the SDK would prefer them to the platform's identity. So is an `AWS_ENDPOINT_URL[_<SERVICE>]`: endpoints
come from `aws.endpoint_url` only. `aws.static_credentials: allow` admits them for development and tests, with a warning.
The shared files (`~/.aws`) are never read. `aws.endpoint_url` sends every call to another endpoint (a VPC
endpoint, an emulator).

## The KEK: two keys

```yaml
keys:
  kind: awskms
  key: arn:aws:kms:eu-central-1:123456789012:key/<id>       # a symmetric encryption key
  mac_key: arn:aws:kms:eu-central-1:123456789012:key/<id>   # an HMAC_256 key
```

- **`key`** wraps the data keys: `Encrypt` and `Decrypt`, with an encryption context
  (`tresor-server: data-key/1`) that KMS checks.
- **`mac_key`** gives the KEK's root, which authenticates every data key (see [Encryption](encryption.md#the-root)):
  `GenerateMac`. A symmetric encryption key does not MAC, hence a second key; HMAC keys exist in every region
  KMS does.
- **ARNs only**, in `aws.region`: an alias or a bare id would make the KEK's id depend on how the key was named.
- **Rotation**: KMS rotates the encryption key's material inside the same key, and old material still decrypts.
  The KEK's id does not change, so no `rewrap` is needed. An HMAC key does not rotate.
- **Another key** (or from a local KEK to KMS): [Moving to another KEK](encryption.md#moving-to-another-kek).

The service's role needs, on the two keys and nothing else:

```json
{
  "Effect": "Allow",
  "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateMac"],
  "Resource": ["arn:aws:kms:eu-central-1:123456789012:key/<key>", "arn:aws:kms:eu-central-1:123456789012:key/<mac_key>"]
}
```

Grant `kms:GenerateMac` to the service's role alone: a role that can wrap and MAC can plant a data key.

## References: Secrets Manager

`ref+aws://<secret>[#<field>][?version=<id>]`

```sql
CREATE PERSISTENT SECRET lake IN corp (
    TYPE s3,
    KEY_ID 'AKIA...',
    SECRET 'ref+aws://duckdb/lake#secret_access_key',
    SCOPE 's3://lake'
);
```

- `<secret>` is the secret's name, in the source's region and account (an ARN is not accepted).
- `#<field>` reads one field of a JSON secret (a text, a number or a boolean); without it, the whole string.
- `?version=<id>` pins one version; staging labels are not accepted. Without it, the current version is read at
  each fetch: a rotation reaches DuckDB at its next fetch.
- A binary secret is refused: a reference is a text value.

```yaml
material:
  aws:
    allow:
      - prefixes: [duckdb/, lake-]     # an entry with no prefixes: every secret the role may read
    cache_ttl: 0s                      # at most 5m
```

The service's role needs `secretsmanager:GetSecretValue` on those secrets (and `kms:Decrypt` on a customer
managed key that encrypts them).

**Another account or region**: a named source ([References](references.md#named-sources)) with an `aws:` of its
own. Its `role_arn` is assumed with the service's identity: the service's role needs `sts:AssumeRole` on it, and
the role in the other account trusts the service's.

```yaml
material:
  sources:
    - name: aws-us
      kind: aws
      aws: {region: us-east-1, role_arn: arn:aws:iam::210987654321:role/tresor-reader}
      allow: [{prefixes: [duckdb/]}]
```

## The database: RDS IAM authentication

```yaml
state:
  kind: postgres
  dsn: host=tresor.abc.eu-central-1.rds.amazonaws.com port=5432 user=tresor dbname=tresor sslmode=verify-full sslrootcert=/etc/rds/global-bundle.pem
  auth: aws
```

- A token is made for each new connection by the service's identity (valid 15 minutes, signed, never stored).
- TLS is required: give the RDS CA bundle and `sslmode=verify-full`.
- The database user is granted `rds_iam`; the role needs `rds-db:connect` on
  `arn:aws:rds-db:<region>:<account>:dbuser:<resource id>/tresor`.
- SQL Server on RDS has no IAM login: a password by reference (`password_ref: ref+aws://…`).

## Token exchange: the assertion signed in KMS

```yaml
issuers:
  - issuer: https://idp.example
    exchange: {client_id: tresor, client_auth: awskms, key: arn:aws:kms:…:key/<id>, kid: <the IdP's name for it>}
```

An asymmetric KMS key (RSA: RS256; ECC NIST P-256: ES256) signs the client assertion; the role needs `kms:Sign`
and `kms:DescribeKey` on it. The IdP is given the key's public half (`aws kms get-public-key`).
