terraform {
  required_version = ">= 1.5"
  required_providers {
    google = { source = "hashicorp/google", version = ">= 6.10, < 8" }
    random = { source = "hashicorp/random", version = ">= 3.6" }
  }
}

provider "google" {
  project = var.project
  region  = var.region
}
