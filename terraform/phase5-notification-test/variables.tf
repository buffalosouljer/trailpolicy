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

# --- Phase 5 specific ---

variable "notification_email" {
  description = "Email address to subscribe to the SNS topic for diff reports"
  type        = string

  validation {
    condition     = can(regex("^[^@]+@[^@]+\\.[^@]+$", var.notification_email))
    error_message = "notification_email must be a valid email address."
  }
}

variable "lambda_source_path" {
  description = "Path to the packaged Lambda zip file"
  type        = string
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
