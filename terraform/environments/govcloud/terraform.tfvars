project_name = "trailpolicy"
environment  = "govcloud"
aws_region   = "us-gov-west-1"

tags = {
  Owner   = "miguel"
  Purpose = "least-privilege-policy-generation"
}

# Phase 1 specific
cloudtrail_trail_name  = "trailpolicy-mgmt-events"
enable_access_analyzer = false # Policy generation not available in GovCloud
access_analyzer_type   = "ACCOUNT"

# Phase 2 specific
athena_workgroup_name      = "trailpolicy-workgroup"
athena_database_name       = "trailpolicy_cloudtrail"
athena_results_bucket_name = "trailpolicy-athena-results"
