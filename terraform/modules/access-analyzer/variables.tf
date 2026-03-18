variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
}

variable "environment" {
  description = "Deployment environment (commercial, govcloud)"
  type        = string
}

variable "enabled" {
  description = "Set to false in GovCloud where policy generation is unavailable"
  type        = bool
  default     = true
}

variable "analyzer_type" {
  description = "Type of Access Analyzer (ACCOUNT or ORGANIZATION)"
  type        = string
  default     = "ACCOUNT"

  validation {
    condition     = contains(["ACCOUNT", "ORGANIZATION"], var.analyzer_type)
    error_message = "Must be ACCOUNT or ORGANIZATION."
  }
}

variable "cloudtrail_bucket_arn" {
  description = "ARN of the CloudTrail S3 bucket for service role access"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key for decryption permissions"
  type        = string
}

variable "archive_rules" {
  description = "Map of archive rule name to filter criteria. Operator defaults to 'eq'; use 'exists' for boolean fields like isPublic."
  type = map(object({
    filter_resource_type = string
    filter_condition     = string
    filter_value         = string
    filter_operator      = optional(string, "eq")
  }))
  default = {}
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}
