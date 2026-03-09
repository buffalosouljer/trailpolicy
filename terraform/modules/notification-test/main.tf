data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  partition     = data.aws_partition.current.partition
  region        = data.aws_region.current.name
  function_name = "${var.project_name}-notification-test"
}

# --- SNS Topic ---

resource "aws_sns_topic" "notifications" {
  name              = "${var.project_name}-policy-diff-notifications"
  kms_master_key_id = var.kms_key_arn

  tags = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# --- CloudWatch Log Group ---

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 14
  kms_key_id        = var.kms_key_arn

  tags = var.tags
}

# --- Lambda IAM Role ---

resource "aws_iam_role" "lambda" {
  name = "${var.project_name}-notification-lambda"

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
  name = "${var.project_name}-notification-base"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
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
        Sid    = "SNSPublish"
        Effect = "Allow"
        Action = "sns:Publish"
        Resource = aws_sns_topic.notifications.arn
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_athena" {
  count = var.enable_athena_source ? 1 : 0

  name = "${var.project_name}-notification-athena"
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

resource "aws_lambda_function" "notification_test" {
  function_name = local.function_name
  role          = aws_iam_role.lambda.arn
  handler       = "handler.handler"
  runtime       = "python3.12"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory
  filename      = var.lambda_source_path

  source_code_hash = filebase64sha256(var.lambda_source_path)

  environment {
    variables = merge(
      {
        SNS_TOPIC_ARN          = aws_sns_topic.notifications.arn
        CLOUDTRAIL_BUCKET_NAME = var.cloudtrail_bucket_name
        KMS_KEY_ARN            = var.kms_key_arn
      },
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
