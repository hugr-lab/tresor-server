# A trial: deletion protection off so that `terraform destroy` removes it.
region              = "eu-central-1"
domain              = "tresor.aws.example.com"
route53_zone_id     = "Z0123456789ABCDEFGHIJ"
issuers             = "[{issuer: 'https://login.microsoftonline.com/<tenant>/v2.0', audience: '<duckdb-secrets client id>', roles_claim: roles}]"
admins              = "[role:secrets_admin]"
deletion_protection = false
