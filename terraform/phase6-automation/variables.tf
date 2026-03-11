variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "trailpolicy"
}

variable "environment" {
  description = "Deployment environment (commercial, govcloud)"
  type        = string

  validation {
    condition     = contains(["commercial", "govcloud"], var.environment)
    error_message = "Environment must be commercial or govcloud."
  }
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}

# --- Phase 1 outputs passed as inputs ---

variable "cloudtrail_bucket_name" {
  description = "Name of the CloudTrail S3 bucket (from Phase 1)"
  type        = string
}

variable "cloudtrail_bucket_arn" {
  description = "ARN of the CloudTrail S3 bucket (from Phase 1)"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key for encryption (from Phase 1)"
  type        = string
}

# --- Phase 6 specific ---

variable "lambda_source_path" {
  description = "Path to the packaged Lambda zip file"
  type        = string
}

variable "target_role_arns" {
  description = "List of IAM role ARNs to generate policies for"
  type        = list(string)
}

variable "schedule_expression" {
  description = "EventBridge schedule expression"
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

  validation {
    condition     = contains(["api", "athena"], var.event_source)
    error_message = "event_source must be \"api\" or \"athena\"."
  }
}

variable "schedule_enabled" {
  description = "Whether the EventBridge schedule rule is enabled"
  type        = bool
  default     = true
}

variable "enable_notifications" {
  description = "Enable SNS notifications"
  type        = bool
  default     = false
}

variable "sns_topic_arn" {
  description = "ARN of existing SNS topic (from Phase 5)"
  type        = string
  default     = ""
}

variable "enable_athena_source" {
  description = "Grant Lambda permissions for Athena queries"
  type        = bool
  default     = false
}

variable "athena_database" {
  description = "Athena database name (from Phase 2, optional)"
  type        = string
  default     = ""
}

variable "athena_table" {
  description = "Athena table name (from Phase 2, optional)"
  type        = string
  default     = ""
}

variable "athena_workgroup" {
  description = "Athena workgroup name (from Phase 2, optional)"
  type        = string
  default     = ""
}

variable "athena_results_bucket_arn" {
  description = "ARN of the Athena results bucket (from Phase 2, optional)"
  type        = string
  default     = ""
}

variable "policy_retention_days" {
  description = "Days to retain generated policies in S3"
  type        = number
  default     = 90
}

# ──────────────────────────────────────────────────────────────────────────────
# Stub variables: declared only so shared terraform.tfvars files do not error.
# These values are NOT used by this phase. Do not rely on their defaults.
# ──────────────────────────────────────────────────────────────────────────────
variable "cloudtrail_trail_name" {
  description = "CloudTrail trail name (used in Phase 1)"
  type        = string
  default     = ""
}

variable "enable_access_analyzer" {
  description = "Enable Access Analyzer (used in Phase 1)"
  type        = bool
  default     = true
}

variable "access_analyzer_type" {
  description = "Access Analyzer type (used in Phase 1)"
  type        = string
  default     = "ACCOUNT"
}

variable "athena_workgroup_name" {
  description = "Athena workgroup name (used in Phase 2)"
  type        = string
  default     = ""
}

variable "athena_database_name" {
  description = "Athena database name (used in Phase 2)"
  type        = string
  default     = ""
}

variable "athena_results_bucket_name" {
  description = "Athena results bucket name (used in Phase 2)"
  type        = string
  default     = ""
}

variable "cloudtrail_s3_prefix" {
  description = "S3 key prefix for CloudTrail logs (used in Phase 2)"
  type        = string
  default     = ""
}
