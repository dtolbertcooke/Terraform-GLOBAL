output "state_bucket_name" {
  value = module.s3_state_bucket.bucket_name
}

output "state_table_name" {
  value = module.dynamodb_state_table.state_table_name
}

output "region" {
  value = var.region
}