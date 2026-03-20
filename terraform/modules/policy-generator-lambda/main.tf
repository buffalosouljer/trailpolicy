data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  partition     = data.aws_partition.current.partition
  region        = data.aws_region.current.name
  function_name = "${var.project_name}-policy-generator"
  bucket_name   = "${var.project_name}-generated-policies-${local.account_id}"
}

# --- S3 Bucket for Generated Policies ---

resource "aws_s3_bucket" "policies" {
  bucket        = local.bucket_name
  force_destroy = var.force_destroy

  tags = var.tags
}

resource "aws_s3_bucket_public_access_block" "policies" {
  bucket = aws_s3_bucket.policies.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "policies" {
  bucket = aws_s3_bucket.policies.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "policies" {
  bucket     = aws_s3_bucket.policies.id
  depends_on = [aws_s3_bucket_public_access_block.policies]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.policies.arn,
          "${aws_s3_bucket.policies.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "policies" {
  bucket = aws_s3_bucket.policies.id

  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "policies" {
  bucket = aws_s3_bucket.policies.id

  rule {
    id     = "expire-old-policies"
    status = "Enabled"

    filter {}

    expiration {
      days = var.policy_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.policy_retention_days
    }
  }
}

# --- CloudWatch Log Group ---

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 14
  kms_key_id        = var.kms_key_arn

  tags = var.tags
}

resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "${local.function_name}-dlq"
  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = var.kms_key_arn
  tags                      = var.tags
}

# --- Lambda IAM Role ---

resource "aws_iam_role" "lambda" {
  name = "${var.project_name}-generator-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "lambda_base" {
  name = "${var.project_name}-generator-base"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.lambda.arn}:*"
      },
      {
        Sid    = "CloudTrailRead"
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents",
          "cloudtrail:DescribeTrails"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudTrailBucketRead"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.cloudtrail_bucket_arn,
          "${var.cloudtrail_bucket_arn}/*"
        ]
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey*"
        ]
        Resource = var.kms_key_arn
      },
      {
        Sid    = "IAMAnalysis"
        Effect = "Allow"
        Action = [
          "iam:GenerateServiceLastAccessedDetails",
          "iam:GetServiceLastAccessedDetails",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:GetRolePolicy",
          "iam:GetPolicy",
          "iam:GetPolicyVersion"
        ]
        Resource = "*"
      },
      {
        Sid    = "OutputBucketWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.policies.arn,
          "${aws_s3_bucket.policies.arn}/*"
        ]
      },
      {
        Sid      = "DLQWrite"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.lambda_dlq.arn
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_sns" {
  count = var.enable_notifications && var.sns_topic_arn != "" ? 1 : 0

  name = "${var.project_name}-generator-sns"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = var.sns_topic_arn
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_athena" {
  count = var.enable_athena_source ? 1 : 0

  name = "${var.project_name}-generator-athena"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AthenaQuery"
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults"
        ]
        Resource = "arn:${local.partition}:athena:${local.region}:${local.account_id}:workgroup/${var.athena_workgroup}"
      },
      {
        Sid    = "GlueCatalog"
        Effect = "Allow"
        Action = [
          "glue:GetTable",
          "glue:GetDatabase"
        ]
        Resource = [
          "arn:${local.partition}:glue:${local.region}:${local.account_id}:catalog",
          "arn:${local.partition}:glue:${local.region}:${local.account_id}:database/${var.athena_database}",
          "arn:${local.partition}:glue:${local.region}:${local.account_id}:table/${var.athena_database}/*"
        ]
      },
      {
        Sid    = "AthenaResultsBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = [
          var.athena_results_bucket_arn,
          "${var.athena_results_bucket_arn}/*"
        ]
      }
    ]
  })
}

# --- Lambda Function ---

resource "aws_lambda_function" "generator" {
  function_name = local.function_name
  role          = aws_iam_role.lambda.arn
  handler       = "handler.handler"
  runtime       = "python3.12"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory
  filename      = var.lambda_source_path

  source_code_hash               = fileexists(var.lambda_source_path) ? filebase64sha256(var.lambda_source_path) : null
  reserved_concurrent_executions = 1

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  environment {
    variables = merge(
      {
        OUTPUT_BUCKET          = aws_s3_bucket.policies.id
        KMS_KEY_ARN            = var.kms_key_arn
        CLOUDTRAIL_BUCKET_NAME = var.cloudtrail_bucket_name
      },
      var.enable_notifications && var.sns_topic_arn != "" ? {
        SNS_TOPIC_ARN = var.sns_topic_arn
      } : {},
      var.enable_athena_source ? {
        ATHENA_DATABASE  = var.athena_database
        ATHENA_TABLE     = var.athena_table
        ATHENA_WORKGROUP = var.athena_workgroup
      } : {}
    )
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.lambda_base,
  ]

  tags = var.tags
}

# --- EventBridge Schedule ---

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.project_name}-policy-generation"
  description         = "Scheduled policy generation for ${length(var.target_role_arns)} roles"
  schedule_expression = var.schedule_expression
  state               = var.schedule_enabled ? "ENABLED" : "DISABLED"

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.generator.arn

  input = jsonencode({
    role_arns = var.target_role_arns
    days      = var.lookback_days
    source    = var.event_source
  })
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.generator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
