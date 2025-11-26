terraform {
  required_version = ">= 1.5.0"
  backend "s3" {
    bucket = "your-tfstate-bucket"
    key    = "infinite-ai/ap-southeast-1/terraform.tfstate"
    region = "ap-southeast-1"
    encrypt = true
  }
}

provider "aws" { region = "ap-southeast-1" }

module "network" {
  source   = "../../modules/network"
  name     = "infinite-ai-apsg"
  region   = "ap-southeast-1"
  vpc_cidr = "10.60.0.0/16"
  tags     = { env = "prod", region = "ap-southeast-1" }
}

module "k8s" {
  source            = "../../modules/k8s"
  name              = "infinite-ai-apsg"
  region            = "ap-southeast-1"
  cluster_role_arn  = "arn:aws:iam::123456789012:role/eksClusterRole"
  subnet_ids        = ["subnet-aaaa", "subnet-bbbb", "subnet-cccc"]
}

module "db" {
  source                 = "../../modules/db"
  name                   = "infinite-ai-apsg"
  region                 = "ap-southeast-1"
  instance_class         = "db.t3.medium"
  subnet_ids             = ["subnet-aaaa", "subnet-bbbb"]
  vpc_security_group_ids = ["sg-xxxxx"]
}
