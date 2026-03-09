output "sns_topic_arn" {
  description = "ARN of the SNS notification topic"
  value       = aws_sns_topic.notifications.arn
}

output "sns_topic_name" {
  description = "Name of the SNS notification topic"
  value       = aws_sns_topic.notifications.name
}

output "lambda_function_arn" {
  description = "ARN of the notification test Lambda function"
  value       = aws_lambda_function.notification_test.arn
}

output "lambda_function_name" {
  description = "Name of the notification test Lambda function"
  value       = aws_lambda_function.notification_test.function_name
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda.arn
}
