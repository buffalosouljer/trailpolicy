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

# --- Phase 1 Specific ---

variable "cloudtrail_trail_name" {
  description = "Name for the CloudTrail trail"
  type        = string
}

variable "enable_access_analyzer" {
  description = "Enable IAM Access Analyzer (false in GovCloud)"
  type        = bool
  default     = true
}

variable "access_analyzer_type" {
  description = "Access Analyzer type (ACCOUNT or ORGANIZATION)"
  type        = string
  default     = "ACCOUNT"
}

variable "trusted_principal_arns" {
  description = "List of IAM principal ARNs that can assume the trailpolicy executor role"
  type        = list(string)
  default     = []
}

variable "executor_external_id" {
  description = "External ID for the trailpolicy executor role AssumeRole condition. Use a unique, unguessable value."
  type        = string
  default     = ""
  sensitive   = true

  validation {
    condition     = var.executor_external_id == "" || length(var.executor_external_id) >= 12
    error_message = "executor_external_id should be empty (uses project_name fallback) or at least 12 characters for confused-deputy protection."
  }
}

variable "force_destroy" {
  description = "Allow S3 buckets to be destroyed even when non-empty. Must be false in production."
  type        = bool
  default     = false
}

variable "enable_cloudwatch_logs" {
  description = "Whether to send CloudTrail events to CloudWatch Logs"
  type        = bool
  default     = false
}

variable "archive_rules" {
  description = "Map of Access Analyzer archive rule name to filter criteria"
  type = map(object({
    filter_resource_type = string
    filter_condition     = string
    filter_value         = string
  }))
  default = {}
}

# ──────────────────────────────────────────────────────────────────────────────
# Stub variables: declared only so shared terraform.tfvars files do not error.
# These values are NOT used by this phase. Do not rely on their defaults.
# ──────────────────────────────────────────────────────────────────────────────
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
