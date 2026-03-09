output "analyzer_arn" {
  description = "ARN of the Access Analyzer (empty string if disabled)"
  value       = var.enabled ? aws_accessanalyzer_analyzer.this[0].arn : ""
}

output "analyzer_service_role_arn" {
  description = "ARN of the IAM role used by Access Analyzer for policy generation"
  value       = var.enabled ? aws_iam_role.analyzer_service[0].arn : ""
}
