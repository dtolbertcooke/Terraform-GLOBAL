# DynamoDB Table for Terraform State Locking
resource "aws_dynamodb_table" "tf_locks" {
  name         = "${var.state_table_name}-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}
