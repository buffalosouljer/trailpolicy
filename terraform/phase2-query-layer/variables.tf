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

variable "cloudtrail_s3_prefix" {
  description = "S3 key prefix under which CloudTrail writes logs (from Phase 1)"
  type        = string
  default     = ""
}

variable "kms_key_arn" {
  description = "ARN of the KMS key for encryption (from Phase 1)"
  type        = string
}

# --- Phase 2 specific ---

variable "athena_workgroup_name" {
  description = "Name of the Athena workgroup"
  type        = string
}

variable "athena_database_name" {
  description = "Name of the Glue catalog database for CloudTrail"
  type        = string
}

variable "athena_results_bucket_name" {
  description = "Name of the S3 bucket for Athena query results"
  type        = string
}

variable "bytes_scanned_limit" {
  description = "Max bytes scanned per query for cost control"
  type        = number
  default     = 10737418240 # 10 GB
}

variable "results_retention_days" {
  description = "Days to retain Athena query results"
  type        = number
  default     = 7
}

# Phase 1 variables (declared so shared tfvars doesn't error, unused here)
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
