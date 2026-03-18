variable "org_name" {
  description = "Organization identifier"
  type        = string

  validation {
    condition     = contains(["org-sbx", "org-fsa", "org-cod"], var.org_name)
    error_message = "org_name must be one of: org-sbx, org-fsa, org-cod."
  }
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-gov-west-1"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "trailpolicy"
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}
