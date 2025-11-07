terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# EKS Cluster
resource "aws_eks_cluster" "infinite_security" {
  name     = "infinite-security-${var.environment}"
  role_arn = aws_iam_role.eks_cluster_role.arn
  version  = "1.28"

  vpc_config {
    subnet_ids = aws_subnet.private[*].id
  }

  tags = {
    Name = "infinite-security-eks"
    Environment = var.environment
  }
}

# RDS PostgreSQL
resource "aws_db_instance" "infinite_security_db" {
  identifier = "infinite-security-${var.environment}"
  engine     = "postgres"
  engine_version = "14.9"
  instance_class = "db.r5.2xlarge"
  allocated_storage = 1000
  storage_encrypted = true
  
  db_name  = "infinite_labyrinth"
  username = "infinite_admin"
  password = var.db_password

  skip_final_snapshot = true

  tags = {
    Name = "infinite-security-db"
    Environment = var.environment
  }
}

# Variables
variable "aws_region" {
  default = "us-east-1"
}

variable "environment" {
  default = "production"
}

variable "db_password" {
  sensitive = true
}

# Outputs
output "eks_cluster_endpoint" {
  value = aws_eks_cluster.infinite_security.endpoint
}

output "rds_endpoint" {
  value = aws_db_instance.infinite_security_db.endpoint
}