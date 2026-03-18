# Populated after running: make bootstrap ORG=org-sbx
# Copy state_bucket_name output → bucket
# Copy dynamodb_table_name output → dynamodb_table
bucket         = ""
dynamodb_table = "trailpolicy-tfstate-lock"
region         = "us-gov-west-1"
encrypt        = true
