output "cloudtrail_bucket_arn" {
  description = "ARN of the CloudTrail S3 bucket"
  value       = module.cloudtrail.cloudtrail_bucket_arn
}

output "cloudtrail_bucket_name" {
  description = "Name of the CloudTrail S3 bucket"
  value       = module.cloudtrail.cloudtrail_bucket_name
}

output "cloudtrail_trail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = module.cloudtrail.cloudtrail_arn
}

output "cloudtrail_s3_prefix" {
  description = "S3 key prefix under which CloudTrail writes logs"
  value       = module.cloudtrail.cloudtrail_s3_prefix
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for encryption"
  value       = aws_kms_key.cloudtrail.arn
}

output "kms_key_id" {
  description = "ID of the KMS key used for encryption"
  value       = aws_kms_key.cloudtrail.key_id
}

output "analyzer_arn" {
  description = "ARN of the Access Analyzer (empty if disabled)"
  value       = module.access_analyzer.analyzer_arn
}

output "trailpolicy_executor_role_arn" {
  description = "ARN of the trailpolicy executor IAM role"
  value       = aws_iam_role.trailpolicy_executor.arn
}

output "trailpolicy_executor_role_name" {
  description = "Name of the trailpolicy executor IAM role"
  value       = aws_iam_role.trailpolicy_executor.name
}
