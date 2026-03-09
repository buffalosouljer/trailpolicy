variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
}

variable "environment" {
  description = "Deployment environment (commercial, govcloud)"
  type        = string
}

variable "notification_email" {
  description = "Email address to subscribe to the SNS topic"
  type        = string
}

variable "lambda_source_path" {
  description = "Path to the packaged Lambda zip containing core lib + handler"
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

variable "athena_database" {
  description = "Athena database name (optional, for athena source)"
  type        = string
  default     = ""
}

variable "athena_table" {
  description = "Athena table name (optional, for athena source)"
  type        = string
  default     = ""
}

variable "athena_workgroup" {
  description = "Athena workgroup name (optional, for athena source)"
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
  default     = 180
}

variable "lambda_memory" {
  description = "Lambda function memory in MB"
  type        = number
  default     = 256
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}
