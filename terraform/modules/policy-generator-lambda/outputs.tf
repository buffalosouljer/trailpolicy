output "lambda_function_arn" {
  description = "ARN of the policy generator Lambda function"
  value       = aws_lambda_function.generator.arn
}

output "lambda_function_name" {
  description = "Name of the policy generator Lambda function"
  value       = aws_lambda_function.generator.function_name
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda.arn
}

output "output_bucket_name" {
  description = "Name of the S3 bucket for generated policies"
  value       = aws_s3_bucket.policies.id
}

output "output_bucket_arn" {
  description = "ARN of the S3 bucket for generated policies"
  value       = aws_s3_bucket.policies.arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge schedule rule"
  value       = aws_cloudwatch_event_rule.schedule.arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge schedule rule"
  value       = aws_cloudwatch_event_rule.schedule.name
}
