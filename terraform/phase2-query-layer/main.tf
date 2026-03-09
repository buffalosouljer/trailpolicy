data "aws_caller_identity" "current" {}

locals {
  common_tags = merge(var.tags, {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Phase       = "2"
  })
}

module "athena_query_layer" {
  source = "../modules/athena-query-layer"

  project_name           = var.project_name
  environment            = var.environment
  database_name          = var.athena_database_name
  workgroup_name         = var.athena_workgroup_name
  cloudtrail_bucket_name = var.cloudtrail_bucket_name
  cloudtrail_bucket_arn  = var.cloudtrail_bucket_arn
  cloudtrail_s3_prefix   = var.cloudtrail_s3_prefix
  aws_account_id         = data.aws_caller_identity.current.account_id
  kms_key_arn            = var.kms_key_arn
  results_bucket_name    = var.athena_results_bucket_name
  bytes_scanned_limit    = var.bytes_scanned_limit
  results_retention_days = var.results_retention_days
  tags                   = local.common_tags
}
