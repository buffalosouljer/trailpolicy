variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
}

variable "environment" {
  description = "Deployment environment (commercial, govcloud)"
  type        = string
}

variable "trail_name" {
  description = "Name for the CloudTrail trail"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key used for CloudTrail log encryption"
  type        = string
}

variable "enable_cloudwatch_logs" {
  description = "Whether to send CloudTrail events to CloudWatch Logs"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}
