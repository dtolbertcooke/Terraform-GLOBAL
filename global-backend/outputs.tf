output "state_bucket_name" {
  value = module.s3_state_bucket.bucket_name
}

output "dynamodb_table_name" {
  value = module.dynamodb_state_table.dynamodb_table_name
}

output "region" {
  value = var.region
}