output "url" {
  description = "The service's public_url: give it to the IdP and the clients."
  value       = local.url
}

output "service_account" {
  description = "The service's identity: grant it nothing more than the recipe does."
  value       = google_service_account.svc.email
}

output "kek" {
  value = google_kms_crypto_key.kek.id
}

output "mac_key" {
  value = "${google_kms_crypto_key.root.id}/cryptoKeyVersions/1"
}

output "database_dns_name" {
  value = trimsuffix(google_sql_database_instance.db.dns_name, ".")
}

output "image" {
  value = local.image
}

output "jobs" {
  description = "The commands: gcloud run jobs execute <job> --region <region> --wait"
  value       = [for j in google_cloud_run_v2_job.commands : j.name]
}
