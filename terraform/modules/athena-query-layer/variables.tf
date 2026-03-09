variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
}

variable "environment" {
  description = "Deployment environment (commercial, govcloud)"
  type        = string
}

variable "database_name" {
  description = "Name of the Glue catalog database"
  type        = string
}

variable "workgroup_name" {
  description = "Name of the Athena workgroup"
  type        = string
}

variable "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket containing CloudTrail logs"
  type        = string
}

variable "cloudtrail_bucket_arn" {
  description = "ARN of the S3 bucket containing CloudTrail logs"
  type        = string
}

variable "cloudtrail_s3_prefix" {
  description = "S3 key prefix under which CloudTrail writes logs"
  type        = string
}

variable "aws_account_id" {
  description = "AWS account ID for partition projection storage location"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key for encrypting Athena results"
  type        = string
}

variable "results_bucket_name" {
  description = "Name of the S3 bucket for Athena query results"
  type        = string
}

variable "bytes_scanned_limit" {
  description = "Max bytes scanned per query (cost control)"
  type        = number
  default     = 10737418240 # 10 GB
}

variable "results_retention_days" {
  description = "Days to retain Athena query results"
  type        = number
  default     = 7
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}
