variable "project" {
  description = "An existing project: the recipe enables the APIs it needs in it."
  type        = string
}

variable "region" {
  description = "Where everything runs."
  type        = string
  default     = "europe-west1"
}

variable "prefix" {
  description = "Every resource's name: lower-case letters, digits and dashes, a letter first."
  type        = string
  default     = "tresor"
  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,13}[a-z0-9])$", var.prefix)) && !strcontains(var.prefix, "--")
    error_message = "prefix: lower-case letters, digits and dashes, a letter first, no dash last or doubled, at most 15 characters."
  }
}

variable "network" {
  description = "An existing VPC's self link for the service's egress and the database's endpoint; empty: a VPC of the recipe's own."
  type        = string
  default     = ""
}

variable "subnetwork" {
  description = "The subnet of var.network (its self link); required with var.network."
  type        = string
  default     = ""
}

variable "image_tag" {
  description = "tresor-server's version (its image's tag on ghcr.io), never edge."
  type        = string
  default     = "v0.8.0"
}

variable "image" {
  description = "An image of your own (Artifact Registry or Docker Hub: Cloud Run takes no other); empty - ghcr.io's, through an Artifact Registry remote repository the recipe makes."
  type        = string
  default     = ""
}

variable "issuers" {
  description = "config issuers, as YAML (the Configuration page): who may call the service."
  type        = string
}

variable "admins" {
  description = "policy.admins, as YAML: the principals that manage secrets."
  type        = string
}

variable "actors" {
  description = "policy.actors, as YAML: servers acting for users (delegation)."
  type        = string
  default     = "[]"
}

variable "material_allow" {
  description = "Where ref+gcp references may read: projects and secret name prefixes. Empty: this project, duckdb-*."
  type = list(object({
    project  = string
    prefixes = list(string)
  }))
  default = []
}

variable "min_instances" {
  description = "The service works in the background (purges, renewals, checks): at least one instance, CPU always allocated."
  type        = number
  default     = 1
  validation {
    condition     = var.min_instances >= 1
    error_message = "min_instances: at least 1."
  }
}

variable "max_instances" {
  type    = number
  default = 3
}

variable "database_tier" {
  description = "Cloud SQL's machine: db-f1-micro for a trial."
  type        = string
  default     = "db-custom-1-3840"
}

variable "deletion_protection" {
  description = "On the database: turn it off only to destroy a trial."
  type        = bool
  default     = true
}
