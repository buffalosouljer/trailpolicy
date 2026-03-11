locals {
  # When cloudtrail_s3_prefix is provided (e.g., "AWSLogs/123456/CloudTrail"),
  # use it directly. When empty, construct the standard CloudTrail path.
  # The prefix should NOT end with a trailing slash — we append one in usage.
  effective_prefix = var.cloudtrail_s3_prefix != "" ? var.cloudtrail_s3_prefix : "AWSLogs/${var.aws_account_id}/CloudTrail"
}

# --- S3 Bucket for Athena Query Results ---

resource "aws_s3_bucket" "athena_results" {
  bucket        = "${var.results_bucket_name}-${var.aws_account_id}"
  force_destroy = var.force_destroy
  tags          = var.tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "athena_results" {
  bucket     = aws_s3_bucket.athena_results.id
  depends_on = [aws_s3_bucket_public_access_block.athena_results]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.athena_results.arn,
          "${aws_s3_bucket.athena_results.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    id     = "expire-query-results"
    status = "Enabled"

    filter {}

    expiration {
      days = var.results_retention_days
    }
  }
}

# --- Glue Catalog Database ---

resource "aws_glue_catalog_database" "this" {
  name = var.database_name
}

# --- Glue Catalog Table (CloudTrail log schema with partition projection) ---

resource "aws_glue_catalog_table" "cloudtrail" {
  name          = var.table_name
  database_name = aws_glue_catalog_database.this.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "projection.enabled"        = "true"
    "projection.region.type"    = "enum"
    "projection.region.values"  = "us-east-1,us-east-2,us-west-1,us-west-2,us-gov-west-1,us-gov-east-1"
    "projection.year.type"      = "integer"
    "projection.year.range"     = "2024,${var.projection_year_end}"
    "projection.month.type"     = "integer"
    "projection.month.range"    = "1,12"
    "projection.month.digits"   = "2"
    "projection.day.type"       = "integer"
    "projection.day.range"      = "1,31"
    "projection.day.digits"     = "2"
    "storage.location.template" = "s3://${var.cloudtrail_bucket_name}/${local.effective_prefix}/$${region}/$${year}/$${month}/$${day}"
    "classification"            = "cloudtrail"
    "EXTERNAL"                  = "TRUE"
  }

  partition_keys {
    name = "region"
    type = "string"
  }

  partition_keys {
    name = "year"
    type = "string"
  }

  partition_keys {
    name = "month"
    type = "string"
  }

  partition_keys {
    name = "day"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${var.cloudtrail_bucket_name}/${local.effective_prefix}/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hive.hcatalog.data.JsonSerDe"

      parameters = {
        "serialization.format" = "1"
      }
    }

    columns {
      name = "eventversion"
      type = "string"
    }

    columns {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>,webidfederationdata:map<string,string>,ec2roledelivery:string>>"
    }

    columns {
      name = "eventtime"
      type = "string"
    }

    columns {
      name = "eventsource"
      type = "string"
    }

    columns {
      name = "eventname"
      type = "string"
    }

    columns {
      name = "awsregion"
      type = "string"
    }

    columns {
      name = "sourceipaddress"
      type = "string"
    }

    columns {
      name = "useragent"
      type = "string"
    }

    columns {
      name = "errorcode"
      type = "string"
    }

    columns {
      name = "errormessage"
      type = "string"
    }

    columns {
      name = "requestparameters"
      type = "string"
    }

    columns {
      name = "responseelements"
      type = "string"
    }

    columns {
      name = "additionaleventdata"
      type = "string"
    }

    columns {
      name = "requestid"
      type = "string"
    }

    columns {
      name = "eventid"
      type = "string"
    }

    columns {
      name = "readonly"
      type = "string"
    }

    columns {
      name = "resources"
      type = "array<struct<arn:string,accountid:string,type:string>>"
    }

    columns {
      name = "eventtype"
      type = "string"
    }

    columns {
      name = "apiversion"
      type = "string"
    }

    columns {
      name = "recipientaccountid"
      type = "string"
    }

    columns {
      name = "serviceeventdetails"
      type = "string"
    }

    columns {
      name = "sharedeventid"
      type = "string"
    }

    columns {
      name = "vpcendpointid"
      type = "string"
    }

    columns {
      name = "tlsdetails"
      type = "struct<tlsversion:string,ciphersuite:string,clientprovidedhostheader:string>"
    }
  }
}

# --- Athena Workgroup ---

resource "aws_athena_workgroup" "this" {
  name          = var.workgroup_name
  force_destroy = true

  configuration {
    enforce_workgroup_configuration = true

    bytes_scanned_cutoff_per_query = var.bytes_scanned_limit

    engine_version {
      selected_engine_version = "Athena engine version 3"
    }

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.id}/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = var.kms_key_arn
      }
    }
  }

  tags = var.tags
}

# --- Athena Named Queries ---

resource "aws_athena_named_query" "events_by_role" {
  name        = "${var.project_name}-events-by-role"
  workgroup   = aws_athena_workgroup.this.name
  database    = aws_glue_catalog_database.this.name
  description = "Query CloudTrail events for a specific role ARN in a date range"

  query = <<-EOQ
    -- Replace <ROLE_ARN>, <REGION>, <START_DATE>, <END_DATE> before running
    -- Date format: YYYY-MM-DD (e.g., 2025-01-15)
    SELECT eventtime, eventsource, eventname, sourceipaddress, useragent,
           errorcode, requestparameters, responseelements, resources,
           useridentity.principalid as principalid,
           useridentity.arn as userarn
    FROM ${aws_glue_catalog_database.this.name}.${aws_glue_catalog_table.cloudtrail.name}
    WHERE useridentity.sessioncontext.sessionissuer.arn = '<ROLE_ARN>'
      AND region = '<REGION>'
      AND date_parse(eventtime, '%Y-%m-%dT%H:%i:%sZ')
          BETWEEN parse_datetime('<START_DATE>', 'yyyy-MM-dd')
              AND parse_datetime('<END_DATE>', 'yyyy-MM-dd') + interval '1' day
      AND (errorcode IS NULL OR errorcode = '')
    ORDER BY eventtime DESC
  EOQ
}

resource "aws_athena_named_query" "action_summary" {
  name        = "${var.project_name}-action-summary"
  workgroup   = aws_athena_workgroup.this.name
  database    = aws_glue_catalog_database.this.name
  description = "Aggregate unique eventSource + eventName by principal"

  query = <<-EOQ
    -- Replace <ROLE_ARN>, <REGION>, <START_DATE>, <END_DATE> before running
    SELECT eventsource, eventname,
           COUNT(*) as invocation_count,
           MIN(eventtime) as first_seen,
           MAX(eventtime) as last_seen
    FROM ${aws_glue_catalog_database.this.name}.${aws_glue_catalog_table.cloudtrail.name}
    WHERE useridentity.sessioncontext.sessionissuer.arn = '<ROLE_ARN>'
      AND region = '<REGION>'
      AND date_parse(eventtime, '%Y-%m-%dT%H:%i:%sZ')
          BETWEEN parse_datetime('<START_DATE>', 'yyyy-MM-dd')
              AND parse_datetime('<END_DATE>', 'yyyy-MM-dd') + interval '1' day
      AND (errorcode IS NULL OR errorcode = '')
    GROUP BY eventsource, eventname
    ORDER BY eventsource, eventname
  EOQ
}

resource "aws_athena_named_query" "resource_summary" {
  name        = "${var.project_name}-resource-summary"
  workgroup   = aws_athena_workgroup.this.name
  database    = aws_glue_catalog_database.this.name
  description = "Extract resource ARNs grouped by action"

  query = <<-EOQ
    -- Replace <ROLE_ARN>, <REGION>, <START_DATE>, <END_DATE> before running
    SELECT eventsource, eventname,
           array_distinct(array_agg(r.arn)) as resource_arns,
           COUNT(*) as invocation_count
    FROM ${aws_glue_catalog_database.this.name}.${aws_glue_catalog_table.cloudtrail.name}
    CROSS JOIN UNNEST(resources) AS t(r)
    WHERE useridentity.sessioncontext.sessionissuer.arn = '<ROLE_ARN>'
      AND region = '<REGION>'
      AND date_parse(eventtime, '%Y-%m-%dT%H:%i:%sZ')
          BETWEEN parse_datetime('<START_DATE>', 'yyyy-MM-dd')
              AND parse_datetime('<END_DATE>', 'yyyy-MM-dd') + interval '1' day
      AND (errorcode IS NULL OR errorcode = '')
    GROUP BY eventsource, eventname
    ORDER BY eventsource, eventname
  EOQ
}
