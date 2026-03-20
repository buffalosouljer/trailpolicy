project_name = "trailpolicy"
environment  = "govcloud"
aws_region   = "us-gov-west-1"

tags = {
  Owner   = "miguel"
  Purpose = "least-privilege-policy-generation"
  Org     = "org-sbx"
}

# Phase 1 specific
cloudtrail_trail_name  = "trailpolicy-mgmt-events"
enable_access_analyzer = false
access_analyzer_type   = "ACCOUNT"

# Phase 2 specific
athena_workgroup_name      = "trailpolicy-workgroup"
athena_database_name       = "trailpolicy_cloudtrail"
athena_results_bucket_name = "trailpolicy-athena-results"

# Phase 1 outputs — fill after deploying Phase 1
# cloudtrail_bucket_name = ""
# cloudtrail_bucket_arn  = ""
# kms_key_arn            = ""

# Phase 5 specific — fill before deploying Phase 5
# notification_email = ""
# lambda_source_path = ""

# Phase 6 specific — fill before deploying Phase 6
# lambda_source_path       = ""
# target_role_arns         = []
# sns_topic_arn            = ""
# enable_notifications     = false
