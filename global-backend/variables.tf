variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "state_bucket_name" {
  description = "Name of the S3 bucket for Terraform state"
  type        = string
}

variable "state_table_name" {
  description = "Name of the DynamoDB table for Terraform locks"
  type        = string
}
variable "environment" {
  description = "Environment (dev, test, prod) for resources"
  type        = string
  default     = "global-infra"
}
variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}
variable "repository" {
  description = "GitHub repository name"
  type        = string
}