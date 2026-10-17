# =============================================================================
# IAM: least-privilege roles
# =============================================================================

# -----------------------------------------------------------------------------
# Application role: can only touch objects in the data bucket.
# Used by the command-line client (src/secure_client.py) via STS AssumeRole.
# -----------------------------------------------------------------------------
resource "aws_iam_role" "app_role" {
  name        = "${var.project_name}-app-role"
  description = "Least-privilege role for applications that read and write the data bucket"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          # Any IAM identity in this account that is itself allowed to assume roles
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "app_s3_access_policy" {
  name        = "${var.project_name}-app-s3-access"
  description = "Read and write access to the data bucket only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowBucketList"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.data_bucket.arn
      },
      {
        Sid      = "AllowObjectReadWrite"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.data_bucket.arn}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "app_role_attachment" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.app_s3_access_policy.arn
}

# -----------------------------------------------------------------------------
# Security auditor role: read-only. Can investigate (S3, CloudTrail,
# Access Analyzer) but cannot change anything.
# -----------------------------------------------------------------------------
resource "aws_iam_role" "security_auditor_role" {
  name        = "${var.project_name}-security-auditor"
  description = "Read-only role for a security analyst investigating the environment"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "auditor_s3_read" {
  role       = aws_iam_role.security_auditor_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "auditor_cloudtrail_read" {
  role       = aws_iam_role.security_auditor_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCloudTrail_ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "auditor_access_analyzer_read" {
  role       = aws_iam_role.security_auditor_role.name
  policy_arn = "arn:aws:iam::aws:policy/IAMAccessAnalyzerReadOnlyAccess"
}
