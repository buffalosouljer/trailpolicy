# --- S3 Bucket for Athena Query Results ---

resource "aws_s3_bucket" "athena_results" {
  bucket        = var.results_bucket_name
  force_destroy = false
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
  name          = "cloudtrail_logs"
  database_name = aws_glue_catalog_database.this.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "projection.enabled"        = "true"
    "projection.region.type"    = "enum"
    "projection.region.values"  = "us-east-1,us-east-2,us-west-1,us-west-2,us-gov-west-1,us-gov-east-1"
    "projection.year.type"      = "integer"
    "projection.year.range"     = "2024,2030"
    "projection.month.type"     = "integer"
    "projection.month.range"    = "1,12"
    "projection.month.digits"   = "2"
    "projection.day.type"       = "integer"
    "projection.day.range"      = "1,31"
    "projection.day.digits"     = "2"
    "storage.location.template" = "s3://${var.cloudtrail_bucket_name}/${var.cloudtrail_s3_prefix}/$${region}/$${year}/$${month}/$${day}"
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
    location      = "s3://${var.cloudtrail_bucket_name}/${var.cloudtrail_s3_prefix}/"
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
  name = var.workgroup_name

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
    SELECT eventtime, eventsource, eventname, awsregion,
           sourceipaddress, errorcode, readonly, resources, requestparameters
    FROM ${aws_glue_catalog_database.this.name}.${aws_glue_catalog_table.cloudtrail.name}
    WHERE useridentity.sessioncontext.sessionissuer.arn = '<ROLE_ARN>'
      AND concat(year, '-', month, '-', day) BETWEEN '<START_DATE>' AND '<END_DATE>'
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
    SELECT eventsource, eventname, COUNT(*) as invocation_count,
           MIN(eventtime) as first_seen, MAX(eventtime) as last_seen
    FROM ${aws_glue_catalog_database.this.name}.${aws_glue_catalog_table.cloudtrail.name}
    WHERE useridentity.sessioncontext.sessionissuer.arn = '<ROLE_ARN>'
      AND concat(year, '-', month, '-', day) BETWEEN '<START_DATE>' AND '<END_DATE>'
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
    SELECT eventsource, eventname,
           transform(resources, x -> x.arn) as resource_arns,
           COUNT(*) as invocation_count
    FROM ${aws_glue_catalog_database.this.name}.${aws_glue_catalog_table.cloudtrail.name}
    WHERE useridentity.sessioncontext.sessionissuer.arn = '<ROLE_ARN>'
      AND concat(year, '-', month, '-', day) BETWEEN '<START_DATE>' AND '<END_DATE>'
      AND (errorcode IS NULL OR errorcode = '')
    GROUP BY eventsource, eventname, resources
    ORDER BY eventsource, eventname
  EOQ
}
