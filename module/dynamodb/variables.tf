variable "state_table_name" {
  description = "Name of the DynamoDB table for Terraform locks"
  type        = string
}
variable "environment" {
  description = "Environment (dev, test, prod) for resources"
  type        = string
  default     = "dev"
}