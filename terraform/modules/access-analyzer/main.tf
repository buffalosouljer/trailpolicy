data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# --- Access Analyzer ---

resource "aws_accessanalyzer_analyzer" "this" {
  count = var.enabled ? 1 : 0

  analyzer_name = "${var.project_name}-analyzer"
  type          = var.analyzer_type
  tags          = var.tags
}

# --- Archive Rules ---

resource "aws_accessanalyzer_archive_rule" "this" {
  for_each = var.enabled ? var.archive_rules : {}

  analyzer_name = aws_accessanalyzer_analyzer.this[0].analyzer_name
  rule_name     = each.key

  filter {
    criteria = "resourceType"
    eq       = [each.value.filter_resource_type]
  }

  filter {
    criteria = each.value.filter_condition
    eq       = [each.value.filter_value]
  }
}

# --- Access Analyzer Service Role for Policy Generation ---

resource "aws_iam_role" "analyzer_service" {
  count = var.enabled ? 1 : 0

  name = "${var.project_name}-analyzer-policy-gen-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "access-analyzer.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "analyzer_service" {
  count = var.enabled ? 1 : 0

  name = "${var.project_name}-analyzer-policy-gen-permissions"
  role = aws_iam_role.analyzer_service[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudTrailAccess"
        Effect = "Allow"
        Action = [
          "cloudtrail:GetTrail",
          "cloudtrail:LookupEvents"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMLastAccessed"
        Effect = "Allow"
        Action = [
          "iam:GenerateServiceLastAccessedDetails",
          "iam:GetServiceLastAccessedDetails"
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
          "kms:DescribeKey"
        ]
        Resource = var.kms_key_arn
      }
    ]
  })
}
