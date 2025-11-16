variable "state_bucket_name" {
  description = "Name of the S3 bucket for Terraform state"
  type        = string
}

variable "environment" {
  description = "Environment (dev, test, prod) for resources"
  type        = string
  default     = "dev"
}