output "state_bucket_name" {
  value = module.s3_state_bucket.bucket_name
}
output "lambda_code_bucket_dev_name" {
  value = module.lambda_code_bucket_dev.bucket_name
}
output "lambda_code_bucket_test_name" {
  value = module.lambda_code_bucket_test.bucket_name
}
output "lambda_code_bucket_prod_name" {
  value = module.lambda_code_bucket_prod.bucket_name
}
output "state_table_name" {
  value = module.dynamodb_state_table.state_table_name
}
output "region" {
  value = var.region
}
