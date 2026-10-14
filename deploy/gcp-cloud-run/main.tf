# tresor-server on Cloud Run (spec 020): its own identity and no key, the KEK in Cloud KMS, references in Secret
# Manager, PostgreSQL in Cloud SQL by IAM authentication over Private Service Connect - no public address - and a
# Cloud Run job per command (spec 019). The README says what to change for production.

data "google_project" "this" {}

locals {
  name   = var.prefix
  number = data.google_project.this.number
  # Cloud Run pulls from Artifact Registry or Docker Hub only: ghcr.io's image through a remote repository
  image = var.image != "" ? var.image : "${var.region}-docker.pkg.dev/${var.project}/${google_artifact_registry_repository.ghcr[0].repository_id}/hugr-lab/tresor-server:${var.image_tag}"
  url   = "https://${local.name}-${local.number}.${var.region}.run.app"
  allow = length(var.material_allow) > 0 ? var.material_allow : [{ project = var.project, prefixes = ["duckdb-"] }]
  # per project, its prefixes together (none: every secret of it)
  allow_by_project = { for p in distinct([for a in local.allow : a.project]) : p => flatten([for a in local.allow : a.prefixes if a.project == p]) }
  own_vpc          = var.network == ""
  network          = local.own_vpc ? google_compute_network.vpc[0].id : var.network
  subnet           = local.own_vpc ? google_compute_subnetwork.subnet[0].id : var.subnetwork
  sql_user         = trimsuffix(google_service_account.svc.email, ".gserviceaccount.com")
  ring             = google_kms_key_ring.ring.id
  commands = {
    reseal          = ["reseal", "-retire"]
    "reseal-rotate" = ["reseal", "-rotate", "-retire"]
    rewrap          = ["rewrap"]
    refs            = ["refs", "-resolve"]
    mac             = ["mac"]
  }
  # the service's settings: the service's and the jobs' (spec 019), one identity and one configuration
  env = {
    TRESOR_LISTEN               = "0.0.0.0:8080"
    TRESOR_PUBLIC_URL           = local.url
    TRESOR_TLS__OFFLOAD         = "true"
    TRESOR_STATE__KIND          = "postgres"
    TRESOR_STATE__DSN           = "host=${trimsuffix(google_sql_database_instance.db.dns_name, ".")} user=${local.sql_user} dbname=tresor sslmode=verify-full sslrootcert=/etc/cloudsql/server-ca.pem"
    TRESOR_STATE__AUTH          = "gcp"
    TRESOR_KEYS__KIND           = "gcpkms"
    TRESOR_KEYS__KEY            = google_kms_crypto_key.kek.id
    TRESOR_KEYS__MAC_KEY        = "${google_kms_crypto_key.root.id}/cryptoKeyVersions/1"
    TRESOR_ISSUERS              = var.issuers
    TRESOR_POLICY__ADMINS       = var.admins
    TRESOR_POLICY__ACTORS       = var.actors
    TRESOR_MATERIAL__GCP__ALLOW = yamlencode(local.allow)
  }
}

resource "google_project_service" "apis" {
  for_each = toset(["run.googleapis.com", "sqladmin.googleapis.com", "cloudkms.googleapis.com",
    "secretmanager.googleapis.com", "compute.googleapis.com", "dns.googleapis.com", "iam.googleapis.com",
  "artifactregistry.googleapis.com"])
  service            = each.value
  disable_on_destroy = false
}

# --- the image: ghcr.io's, through a remote repository (Cloud Run pulls from Artifact Registry or Docker Hub) ---

resource "google_artifact_registry_repository" "ghcr" {
  count         = var.image == "" ? 1 : 0
  repository_id = "${local.name}-ghcr"
  location      = var.region
  format        = "DOCKER"
  mode          = "REMOTE_REPOSITORY"
  description   = "ghcr.io, for tresor-server's image"
  remote_repository_config {
    docker_repository {
      custom_repository {
        uri = "https://ghcr.io"
      }
    }
  }
  depends_on = [google_project_service.apis]
}

# --- the network: the service's egress and the database's endpoint, private ----------------------------------

resource "google_compute_network" "vpc" {
  count                   = local.own_vpc ? 1 : 0
  name                    = "${local.name}-vpc"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "subnet" {
  count                    = local.own_vpc ? 1 : 0
  name                     = "${local.name}-subnet"
  network                  = google_compute_network.vpc[0].id
  region                   = var.region
  ip_cidr_range            = "10.10.0.0/24"
  private_ip_google_access = true # for workloads that egress all traffic through the VPC; harmless here
}

# --- the service's identity: no key ---------------------------------------------------------------------------

resource "google_service_account" "svc" {
  account_id   = "${local.name}-svc"
  display_name = "tresor-server"
  depends_on   = [google_project_service.apis]
}

# --- the KEK: a key that wraps the data keys, and a MAC key whose version gives the root ----------------------

resource "google_kms_key_ring" "ring" {
  name       = local.name
  location   = var.region
  depends_on = [google_project_service.apis]
}

resource "google_kms_crypto_key" "kek" {
  name            = "kek"
  key_ring        = google_kms_key_ring.ring.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = "7776000s" # 90 days: then tresor-server rewrap (the <prefix>-rewrap job) moves the data keys
}

resource "google_kms_crypto_key" "root" {
  name     = "root"
  key_ring = google_kms_key_ring.ring.id
  purpose  = "MAC"
  version_template {
    algorithm = "HMAC_SHA256" # not rotated: the root must stay the same
  }
}

resource "google_kms_crypto_key_iam_member" "kek" {
  for_each      = toset(["roles/cloudkms.cryptoKeyEncrypterDecrypter", "roles/cloudkms.viewer"])
  crypto_key_id = google_kms_crypto_key.kek.id
  role          = each.value
  member        = google_service_account.svc.member
}

# the MAC key is the service's alone: who can wrap and MAC can plant a data key
resource "google_kms_crypto_key_iam_member" "root" {
  crypto_key_id = google_kms_crypto_key.root.id
  role          = "roles/cloudkms.signer"
  member        = google_service_account.svc.member
}

# --- references: Secret Manager, within the allowlist ---------------------------------------------------------

data "google_project" "allowed" {
  for_each   = toset([for a in local.allow : a.project])
  project_id = each.value
}

resource "google_project_iam_member" "secrets" {
  for_each = local.allow_by_project
  project  = each.key
  role     = "roles/secretmanager.secretAccessor"
  member   = google_service_account.svc.member
  dynamic "condition" {
    for_each = length(each.value) > 0 ? [1] : [] # no prefix: every secret of the project
    content {
      title      = "${local.name}-allowlist"
      expression = join(" || ", [for p in each.value : "resource.name.startsWith(\"projects/${data.google_project.allowed[each.key].number}/secrets/${p}\")"])
    }
  }
}

# --- the database: Cloud SQL, IAM authentication, Private Service Connect, no public address -----------------

resource "google_sql_database_instance" "db" {
  name                = "${local.name}-pg"
  database_version    = "POSTGRES_16"
  region              = var.region
  deletion_protection = var.deletion_protection
  settings {
    tier              = var.database_tier
    edition           = "ENTERPRISE"
    availability_type = "ZONAL"
    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }
    ip_configuration {
      ipv4_enabled   = false
      ssl_mode       = "ENCRYPTED_ONLY"
      server_ca_mode = "GOOGLE_MANAGED_CAS_CA" # a DNS name in the certificate: verify-full
      psc_config {
        psc_enabled               = true
        allowed_consumer_projects = [var.project]
      }
    }
  }
  depends_on = [google_project_service.apis]
}

resource "google_sql_database" "tresor" {
  name            = "tresor"
  instance        = google_sql_database_instance.db.name
  deletion_policy = "ABANDON" # owned by the service's IAM user: Cloud SQL refuses to drop it; it goes with the instance
}

resource "google_sql_user" "svc" {
  name            = local.sql_user
  instance        = google_sql_database_instance.db.name
  type            = "CLOUD_IAM_SERVICE_ACCOUNT"
  deletion_policy = "ABANDON" # it owns the database: Cloud SQL refuses to delete it; the instance goes with it
}

# cloudsql.instances.login (IAM authentication over PSC; cloudsql.client is the connector's), on this instance only
resource "google_project_iam_member" "sql" {
  project = var.project
  role    = "roles/cloudsql.instanceUser"
  member  = google_service_account.svc.member
  condition {
    title      = "${local.name}-pg"
    expression = "resource.name == \"projects/${var.project}/instances/${local.name}-pg\""
  }
}

# the endpoint: an internal address in the subnet, to the instance's service attachment
resource "google_compute_address" "db" {
  name         = "${local.name}-pg"
  region       = var.region
  subnetwork   = local.subnet
  address_type = "INTERNAL"
}

resource "google_compute_forwarding_rule" "db" {
  name                  = "${local.name}-pg"
  region                = var.region
  network               = local.network
  ip_address            = google_compute_address.db.id
  target                = google_sql_database_instance.db.psc_service_attachment_link
  load_balancing_scheme = ""
}

# the instance's DNS name resolves only through a private zone of one's own: the name its certificate carries
resource "google_dns_managed_zone" "db" {
  name        = "${local.name}-pg"
  dns_name    = google_sql_database_instance.db.dns_name
  description = "Cloud SQL's DNS name, for verify-full (tresor-server)"
  visibility  = "private"
  private_visibility_config {
    networks {
      network_url = local.network
    }
  }
}

resource "google_dns_record_set" "db" {
  name         = google_sql_database_instance.db.dns_name
  managed_zone = google_dns_managed_zone.db.name
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_address.db.address]
}

# the instance's CA, for sslrootcert: a file the service and the jobs mount
resource "google_secret_manager_secret" "ca" {
  secret_id = "${local.name}-sql-ca"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "ca" {
  secret      = google_secret_manager_secret.ca.id
  secret_data = join("\n", [for c in google_sql_database_instance.db.server_ca_cert : c.cert])
}

resource "google_secret_manager_secret_iam_member" "ca" {
  secret_id = google_secret_manager_secret.ca.id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.svc.member
}

# --- the database's ownership: once, as postgres, whose password then dies -----------------------------------

resource "random_password" "postgres" {
  length  = 32
  special = false
}

resource "google_sql_user" "postgres" {
  name            = "postgres"
  instance        = google_sql_database_instance.db.name
  password        = random_password.postgres.result # replaced by the job below: dead once it ran
  deletion_policy = "ABANDON"                       # the built-in user: never deleted
  lifecycle {
    ignore_changes = all # an update would set the dead password again
  }
}

resource "google_secret_manager_secret" "init" {
  secret_id = "${local.name}-sql-init"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "init" {
  secret      = google_secret_manager_secret.init.id
  secret_data = random_password.postgres.result
}

resource "google_secret_manager_secret_iam_member" "init" {
  secret_id = google_secret_manager_secret.init.id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.svc.member
}

resource "google_cloud_run_v2_job" "db_init" {
  name                = "${local.name}-db-init"
  location            = var.region
  deletion_protection = false
  template {
    template {
      service_account = google_service_account.svc.email
      max_retries     = 0
      timeout         = "300s"
      containers {
        image   = "docker.io/library/postgres:16-alpine"
        command = ["psql"]
        args = [
          "host=${google_compute_address.db.address} user=postgres dbname=tresor sslmode=verify-ca sslrootcert=/etc/cloudsql/server-ca.pem",
          "-v", "ON_ERROR_STOP=1", "-c",
          "GRANT \"${local.sql_user}\" TO postgres; ALTER DATABASE tresor OWNER TO \"${local.sql_user}\"; DO $$ BEGIN EXECUTE format('ALTER ROLE postgres PASSWORD %L', replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '')); END $$;",
        ]
        env {
          name = "PGPASSWORD"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.init.secret_id
              version = "latest"
            }
          }
        }
        volume_mounts {
          name       = "ca"
          mount_path = "/etc/cloudsql"
        }
      }
      volumes {
        name = "ca"
        secret {
          secret = google_secret_manager_secret.ca.secret_id
          items {
            version = "latest"
            path    = "server-ca.pem"
          }
        }
      }
      vpc_access {
        network_interfaces {
          network    = local.network
          subnetwork = local.subnet
        }
        egress = "PRIVATE_RANGES_ONLY"
      }
    }
  }
  depends_on = [google_secret_manager_secret_version.init, google_secret_manager_secret_iam_member.init,
    google_secret_manager_secret_iam_member.ca, google_sql_user.postgres, google_sql_user.svc, google_sql_database.tresor,
  google_dns_record_set.db, google_compute_forwarding_rule.db]
}

# runs the job once (again when the instance, the database or the user is replaced): gcloud where Terraform runs.
# Retried: the job's grants on its secrets take a while to reach Secret Manager. Then the first password's
# version is disabled - it is dead anyway.
resource "terraform_data" "db_init" {
  triggers_replace = [google_sql_database_instance.db.id, google_sql_database.tresor.id, google_sql_user.svc.id]
  provisioner "local-exec" {
    command = <<-EOT
      for i in 1 2 3 4 5 6; do
        if gcloud run jobs execute ${google_cloud_run_v2_job.db_init.name} --project ${var.project} --region ${var.region} --wait; then
          gcloud secrets versions disable latest --secret ${google_secret_manager_secret.init.secret_id} --project ${var.project} --quiet
          exit 0
        fi
        sleep 20
      done
      exit 1
    EOT
  }
}

# --- the service -------------------------------------------------------------------------------------------------

resource "google_cloud_run_v2_service" "svc" {
  name                = local.name
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = false
  # the service authenticates every request itself (its issuers' tokens): no Cloud Run invoker check - and no
  # allUsers binding, which an organization's domain-restricted sharing refuses
  invoker_iam_disabled = true
  template {
    service_account = google_service_account.svc.email
    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }
    vpc_access {
      network_interfaces {
        network    = local.network
        subnetwork = local.subnet
      }
      egress = "PRIVATE_RANGES_ONLY"
    }
    containers {
      image = local.image
      ports {
        container_port = 8080
      }
      resources {
        cpu_idle = false # CPU always: the service purges, renews and checks in the background
        limits   = { cpu = "1", memory = "512Mi" }
      }
      dynamic "env" {
        for_each = local.env
        content {
          name  = env.key
          value = env.value
        }
      }
      volume_mounts {
        name       = "ca"
        mount_path = "/etc/cloudsql"
      }
      startup_probe {
        http_get {
          path = "/healthz"
        }
        period_seconds    = 5
        failure_threshold = 30
      }
      liveness_probe {
        http_get {
          path = "/healthz"
        }
        period_seconds = 10
      }
    }
    volumes {
      name = "ca"
      secret {
        secret = google_secret_manager_secret.ca.secret_id
        items {
          version = "latest"
          path    = "server-ca.pem"
        }
      }
    }
  }
  depends_on = [terraform_data.db_init, google_kms_crypto_key_iam_member.kek, google_kms_crypto_key_iam_member.root,
  google_project_iam_member.sql, google_secret_manager_secret_iam_member.ca]
}

# --- the commands as jobs (spec 019): gcloud run jobs execute <prefix>-reseal --region <region> --wait --------

resource "google_cloud_run_v2_job" "commands" {
  for_each            = local.commands
  name                = "${local.name}-${each.key}"
  location            = var.region
  deletion_protection = false
  template {
    template {
      service_account = google_service_account.svc.email
      max_retries     = 0 # a command is not retried: its log says what to do
      timeout         = "3600s"
      containers {
        image = local.image
        args  = each.value
        resources {
          limits = { cpu = "1", memory = "512Mi" }
        }
        dynamic "env" {
          for_each = local.env
          content {
            name  = env.key
            value = env.value
          }
        }
        volume_mounts {
          name       = "ca"
          mount_path = "/etc/cloudsql"
        }
      }
      volumes {
        name = "ca"
        secret {
          secret = google_secret_manager_secret.ca.secret_id
          items {
            version = "latest"
            path    = "server-ca.pem"
          }
        }
      }
      vpc_access {
        network_interfaces {
          network    = local.network
          subnetwork = local.subnet
        }
        egress = "PRIVATE_RANGES_ONLY"
      }
    }
  }
  depends_on = [terraform_data.db_init]
}
