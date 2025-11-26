terraform {
  required_version = ">= 1.5.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.27"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.13"
    }
  }
}

provider "kubernetes" {}
provider "helm" {
  kubernetes {}
}

resource "helm_release" "minio" {
  name       = var.name
  repository = "https://charts.min.io/"
  chart      = "minio"
  namespace  = var.namespace

  values = [
    yamlencode({
      mode = "distributed"
      replicas = 4
      resources = {
        requests = { cpu = "200m", memory = "512Mi" }
        limits   = { cpu = "1",    memory = "1Gi" }
      }
      persistence = { enabled = true, size = "20Gi" }
    })
  ]
}
