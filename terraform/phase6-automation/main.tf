locals {
  common_tags = merge(var.tags, {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Phase       = "6"
  })
}

module "policy_generator" {
  source = "../modules/policy-generator-lambda"

  project_name           = var.project_name
  environment            = var.environment
  lambda_source_path     = var.lambda_source_path
  cloudtrail_bucket_arn  = var.cloudtrail_bucket_arn
  cloudtrail_bucket_name = var.cloudtrail_bucket_name
  kms_key_arn            = var.kms_key_arn
  target_role_arns       = var.target_role_arns
  schedule_expression    = var.schedule_expression
  lookback_days          = var.lookback_days
  event_source           = var.event_source

  # Notifications
  enable_notifications = var.enable_notifications
  sns_topic_arn        = var.sns_topic_arn

  # Optional Athena integration
  enable_athena_source      = var.enable_athena_source
  athena_database           = var.athena_database
  athena_table              = var.athena_table
  athena_workgroup          = var.athena_workgroup
  athena_results_bucket_arn = var.athena_results_bucket_arn

  # Tuning
  policy_retention_days = var.policy_retention_days

  tags = local.common_tags
}
