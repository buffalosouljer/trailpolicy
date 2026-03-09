output "athena_database_name" {
  description = "Name of the Glue catalog database"
  value       = module.athena_query_layer.athena_database_name
}

output "athena_table_name" {
  description = "Name of the Glue catalog table for CloudTrail logs"
  value       = module.athena_query_layer.athena_table_name
}

output "athena_workgroup_name" {
  description = "Name of the Athena workgroup"
  value       = module.athena_query_layer.athena_workgroup_name
}

output "athena_results_bucket_arn" {
  description = "ARN of the Athena results S3 bucket"
  value       = module.athena_query_layer.athena_results_bucket_arn
}
