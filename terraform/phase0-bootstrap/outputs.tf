output "state_bucket_name" {
  description = "S3 bucket name — use as 'bucket' in backend.hcl"
  value       = aws_s3_bucket.tfstate.id
}

output "state_bucket_arn" {
  description = "S3 bucket ARN"
  value       = aws_s3_bucket.tfstate.arn
}

output "dynamodb_table_name" {
  description = "DynamoDB table name — use as 'dynamodb_table' in backend.hcl"
  value       = aws_dynamodb_table.tfstate_lock.name
}
