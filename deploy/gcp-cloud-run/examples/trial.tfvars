# A trial: a small database, deletion protection off so that `terraform destroy` removes it.
project             = "my-project"
region              = "europe-west1"
issuers             = "[{issuer: 'https://login.microsoftonline.com/<tenant>/v2.0', audience: '<duckdb-secrets client id>', roles_claim: roles}]"
admins              = "[role:secrets_admin]"
database_tier       = "db-f1-micro"
deletion_protection = false
