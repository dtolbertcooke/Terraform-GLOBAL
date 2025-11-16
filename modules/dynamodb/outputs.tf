output "state_table_name" {
  value = aws_dynamodb_table.tf_locks.name
}