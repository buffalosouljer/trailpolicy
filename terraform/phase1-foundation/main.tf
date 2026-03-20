data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  common_tags = merge(var.tags, {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Phase       = "1"
  })

  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.name
}

# --- KMS Key for CloudTrail encryption ---

resource "aws_kms_key" "cloudtrail" {
  description             = "${var.project_name} CloudTrail encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${local.partition}:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailEncrypt"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"
          }
        }
      },
      {
        Sid    = "AllowTrailpolicyDecrypt"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.trailpolicy_executor.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"
          }
        }
      },
      {
        Sid    = "AllowCloudWatchLogsEncrypt"
        Effect = "Allow"
        Principal = {
          Service = "logs.${local.region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:*"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.project_name}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

# --- CloudTrail Module ---

module "cloudtrail" {
  source = "../modules/cloudtrail"

  project_name           = var.project_name
  environment            = var.environment
  trail_name             = var.cloudtrail_trail_name
  kms_key_arn            = aws_kms_key.cloudtrail.arn
  enable_cloudwatch_logs = var.enable_cloudwatch_logs
  force_destroy          = var.force_destroy
  tags                   = var.tags
}

# --- Access Analyzer Module ---

module "access_analyzer" {
  source = "../modules/access-analyzer"

  project_name          = var.project_name
  environment           = var.environment
  enabled               = var.enable_access_analyzer
  analyzer_type         = var.access_analyzer_type
  cloudtrail_bucket_arn = module.cloudtrail.cloudtrail_bucket_arn
  kms_key_arn           = aws_kms_key.cloudtrail.arn
  archive_rules         = var.archive_rules
  tags                  = var.tags
}

# --- trailpolicy Executor Role ---

resource "aws_iam_role" "trailpolicy_executor" {
  name = "${var.project_name}-executor"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = length(var.trusted_principal_arns) > 0 ? var.trusted_principal_arns : ["arn:${local.partition}:iam::${local.account_id}:root"]
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.executor_external_id != "" ? var.executor_external_id : var.project_name
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "trailpolicy_executor" {
  name = "${var.project_name}-executor-policy"
  role = aws_iam_role.trailpolicy_executor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudTrailRead"
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents",
          "cloudtrail:GetTrailStatus",
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
          module.cloudtrail.cloudtrail_bucket_arn,
          "${module.cloudtrail.cloudtrail_bucket_arn}/*"
        ]
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.cloudtrail.arn
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
        Sid    = "AthenaQuery"
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults"
        ]
        Resource = "arn:${local.partition}:athena:${local.region}:${local.account_id}:workgroup/${var.athena_workgroup_name != "" ? var.athena_workgroup_name : "${var.project_name}-workgroup"}"
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
          "arn:${local.partition}:glue:${local.region}:${local.account_id}:database/${var.athena_database_name != "" ? var.athena_database_name : "${var.project_name}_cloudtrail"}",
          "arn:${local.partition}:glue:${local.region}:${local.account_id}:table/${var.athena_database_name != "" ? var.athena_database_name : "${var.project_name}_cloudtrail"}/*"
        ]
      }
    ]
  })
}
