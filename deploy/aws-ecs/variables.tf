variable "region" {
  type    = string
  default = "eu-central-1"
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

variable "vpc_id" {
  description = "An existing VPC; empty: one of the recipe's own (two AZs, a NAT gateway)."
  type        = string
  default     = ""
}

variable "private_subnet_ids" {
  description = "With vpc_id: the private subnets (two AZs at least) the tasks and the database run in; they reach the internet through a NAT."
  type        = list(string)
  default     = []
}

variable "public_subnet_ids" {
  description = "With vpc_id: the public subnets the load balancer runs in."
  type        = list(string)
  default     = []
}

variable "vpc_endpoints" {
  description = "Interface endpoints for KMS, Secrets Manager and CloudWatch Logs: the tasks' traffic to them stays in the VPC (~$7 a month per endpoint and AZ). The NAT stays for the IdP and the images."
  type        = bool
  default     = false
}

variable "domain" {
  description = "The service's name, its public_url: https://<domain>."
  type        = string
}

variable "route53_zone_id" {
  description = "A Route 53 zone holding domain: the certificate validated and the name pointed at the load balancer by the recipe. Empty: certificate_arn is required, and the name is pointed by hand (output lb_dns_name)."
  type        = string
  default     = ""
}

variable "certificate_arn" {
  description = "An issued ACM certificate for domain; empty: one made and validated in route53_zone_id."
  type        = string
  default     = ""
  validation {
    condition     = var.certificate_arn != "" || var.route53_zone_id != ""
    error_message = "certificate_arn or route53_zone_id: the HTTPS listener needs a certificate - one issued, or one the recipe validates in the zone."
  }
}

variable "image" {
  description = "tresor-server's image: a version, never edge. Pulled through the NAT."
  type        = string
  default     = "ghcr.io/hugr-lab/tresor-server:v0.8.1"
}

variable "issuers" {
  description = "config issuers, as YAML (the Configuration page)."
  type        = string
}

variable "admins" {
  description = "policy.admins, as YAML."
  type        = string
}

variable "actors" {
  description = "policy.actors, as YAML."
  type        = string
  default     = "[]"
}

variable "material_prefixes" {
  description = "Secrets Manager name prefixes ref+aws may read in this account and region (material.aws.allow)."
  type        = list(string)
  default     = ["duckdb/"]
  validation {
    condition     = length(var.material_prefixes) > 0 && alltrue([for p in var.material_prefixes : p != ""])
    error_message = "material_prefixes: at least one, none empty - the service reads no more than these."
  }
}

variable "desired_count" {
  type    = number
  default = 2
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro"
}

variable "deletion_protection" {
  description = "On the database and the load balancer: turn it off only to destroy a trial."
  type        = bool
  default     = true
}
