locals {
  common_tags = merge(var.tags, {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Phase       = "5"
  })
}

module "notification_test" {
  source = "../modules/notification-test"

  project_name           = var.project_name
  environment            = var.environment
  notification_email     = var.notification_email
  lambda_source_path     = var.lambda_source_path
  cloudtrail_bucket_arn  = var.cloudtrail_bucket_arn
  cloudtrail_bucket_name = var.cloudtrail_bucket_name
  kms_key_arn            = var.kms_key_arn

  # Optional Athena integration
  enable_athena_source      = var.enable_athena_source
  athena_database           = var.athena_database
  athena_table              = var.athena_table
  athena_workgroup          = var.athena_workgroup
  athena_results_bucket_arn = var.athena_results_bucket_arn

  tags = var.tags
}
