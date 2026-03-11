output "sns_topic_arn" {
  description = "ARN of the SNS notification topic (reused by Phase 6)"
  value       = module.notification_test.sns_topic_arn
}

output "sns_topic_name" {
  description = "Name of the SNS notification topic"
  value       = module.notification_test.sns_topic_name
}

output "lambda_function_arn" {
  description = "ARN of the notification test Lambda function"
  value       = module.notification_test.lambda_function_arn
}

output "lambda_function_name" {
  description = "Name of the notification test Lambda function"
  value       = module.notification_test.lambda_function_name
}

output "lambda_role_arn" {
  description = "ARN of the notification test Lambda execution role"
  value       = module.notification_test.lambda_role_arn
}
