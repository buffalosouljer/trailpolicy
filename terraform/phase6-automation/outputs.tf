output "lambda_function_arn" {
  description = "ARN of the policy generator Lambda function"
  value       = module.policy_generator.lambda_function_arn
}

output "lambda_function_name" {
  description = "Name of the policy generator Lambda function"
  value       = module.policy_generator.lambda_function_name
}

output "output_bucket_name" {
  description = "Name of the S3 bucket for generated policies"
  value       = module.policy_generator.output_bucket_name
}

output "output_bucket_arn" {
  description = "ARN of the S3 bucket for generated policies"
  value       = module.policy_generator.output_bucket_arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge schedule rule"
  value       = module.policy_generator.eventbridge_rule_name
}

output "lambda_role_arn" {
  description = "ARN of the policy generator Lambda execution role"
  value       = module.policy_generator.lambda_role_arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge schedule rule"
  value       = module.policy_generator.eventbridge_rule_arn
}
