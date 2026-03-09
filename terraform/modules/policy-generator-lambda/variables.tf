variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
}

variable "environment" {
  description = "Deployment environment (commercial, govcloud)"
  type        = string
}

variable "lambda_source_path" {
  description = "Path to the packaged Lambda deployment zip"
  type        = string
}

variable "cloudtrail_bucket_arn" {
  description = "ARN of the CloudTrail S3 bucket"
  type        = string
}

variable "cloudtrail_bucket_name" {
  description = "Name of the CloudTrail S3 bucket"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key for encryption"
  type        = string
}

variable "target_role_arns" {
  description = "List of IAM role ARNs to generate policies for"
  type        = list(string)
}

variable "schedule_expression" {
  description = "EventBridge schedule expression (cron or rate)"
  type        = string
  default     = "cron(0 6 ? * MON *)"
}

variable "lookback_days" {
  description = "Number of days to look back in CloudTrail"
  type        = number
  default     = 30
}

variable "event_source" {
  description = "Event data source (api or athena)"
  type        = string
  default     = "api"
}

variable "enable_notifications" {
  description = "Enable SNS notifications for automation results"
  type        = bool
  default     = false
}

variable "sns_topic_arn" {
  description = "ARN of existing SNS topic for notifications (from Phase 5)"
  type        = string
  default     = ""
}

variable "athena_database" {
  description = "Athena database name (optional)"
  type        = string
  default     = ""
}

variable "athena_table" {
  description = "Athena table name (optional)"
  type        = string
  default     = ""
}

variable "athena_workgroup" {
  description = "Athena workgroup name (optional)"
  type        = string
  default     = ""
}

variable "athena_results_bucket_arn" {
  description = "ARN of the Athena results bucket (optional)"
  type        = string
  default     = ""
}

variable "enable_athena_source" {
  description = "Grant Lambda permissions for Athena queries"
  type        = bool
  default     = false
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 300
}

variable "lambda_memory" {
  description = "Lambda function memory in MB"
  type        = number
  default     = 512
}

variable "policy_retention_days" {
  description = "Days to retain generated policies in S3"
  type        = number
  default     = 90
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}
