terraform {
  required_version = "= 1.15.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.55.0"
    }
  }
}

variable "aws_region" {
  description = "AWS region containing the governed AgentGate sandbox target."
  type        = string
}

variable "demo_bucket_name" {
  description = "Name of the tagged, governed sandbox bucket."
  type        = string
}

variable "demo_bucket_prefix" {
  description = "Only S3 key prefix the Vault-issued role may manage."
  type        = string
}

variable "request_id" {
  description = "Signed AgentGate request correlation identifier."
  type        = string
}

provider "aws" {
  region = var.aws_region
}

data "aws_s3_bucket" "governed" {
  bucket = var.demo_bucket_name
}

resource "aws_s3_object" "plan_marker" {
  bucket = data.aws_s3_bucket.governed.id
  key    = "${var.demo_bucket_prefix}plans/${var.request_id}.txt"

  content      = "AgentGate governed Terraform plan for request ${var.request_id}\n"
  content_type = "text/plain"

  metadata = {
    agentgate-request-id = var.request_id
  }
}

output "planned_marker" {
  description = "Credential-free S3 target that this plan would create."
  value       = "s3://${aws_s3_object.plan_marker.bucket}/${aws_s3_object.plan_marker.key}"
}
