# -----------------------------------------------------------------------------
# Application Role (Least Privilege)
# -----------------------------------------------------------------------------
resource "aws_iam_role" "app_role" {
  name = "${var.project_name}-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          # In a real scenario, this would be an EC2 instance, Lambda, or a specific user
          # For this project, we'll allow the current account to assume it
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    ]
  })
}

# Policy allowing read/write only to the specific data bucket
resource "aws_iam_policy" "app_s3_access_policy" {
  name        = "${var.project_name}-app-s3-access"
  description = "Allows read and write access to the specific data bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowBucketList"
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.data_bucket.arn
      },
      {
        Sid    = "AllowObjectReadWrite"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
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
# Admin Role (Security Analyst)
# -----------------------------------------------------------------------------
resource "aws_iam_role" "security_admin_role" {
  name = "${var.project_name}-security-admin"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    ]
  })
}

# Attach AWS managed policy for S3 Full Access
# In a stricter environment, this would be narrowed down, but for demonstration 
# of different role types, this is acceptable.
resource "aws_iam_role_policy_attachment" "security_admin_s3" {
  role       = aws_iam_role.security_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_role_policy_attachment" "security_admin_cloudtrail" {
  role       = aws_iam_role.security_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCloudTrail_ReadOnlyAccess"
}
