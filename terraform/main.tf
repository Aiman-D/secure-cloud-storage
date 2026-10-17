# =============================================================================
# Storage layer: a private data bucket, plus a logging bucket for CloudTrail
# and S3 server access logs.
# =============================================================================

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# -----------------------------------------------------------------------------
# Logging bucket (CloudTrail logs + S3 access logs)
# -----------------------------------------------------------------------------
#tfsec:ignore:aws-s3-enable-bucket-logging Access-logging the log bucket into itself would create an endless loop of log files
resource "aws_s3_bucket" "logging_bucket" {
  bucket        = "${var.project_name}-logs-${random_string.suffix.result}"
  force_destroy = true # lets `terraform destroy` clean up a student project
}

resource "aws_s3_bucket_public_access_block" "logging_bucket_pab" {
  bucket = aws_s3_bucket.logging_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#tfsec:ignore:aws-s3-encryption-customer-key A customer-managed KMS key costs about $1/month; SSE-S3 keeps this inside the free tier
resource "aws_s3_bucket_server_side_encryption_configuration" "logging_bucket_sse" {
  bucket = aws_s3_bucket.logging_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "logging_bucket_versioning" {
  bucket = aws_s3_bucket.logging_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logging_bucket_lifecycle" {
  bucket = aws_s3_bucket.logging_bucket.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    filter {}

    expiration {
      days = 90
    }
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.logging_bucket_versioning]
}

resource "aws_s3_bucket_policy" "logging_bucket_policy" {
  bucket = aws_s3_bucket.logging_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.logging_bucket.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logging_bucket.arn}/cloudtrail/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      },
      {
        Sid       = "S3ServerAccessLogsWrite"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logging_bucket.arn}/s3-access-logs/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
        }
      },
      {
        Sid       = "EnforceHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.logging_bucket.arn,
          "${aws_s3_bucket.logging_bucket.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.logging_bucket_pab]
}

# -----------------------------------------------------------------------------
# Primary data bucket (the files users upload)
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "data_bucket" {
  bucket        = "${var.project_name}-data-${random_string.suffix.result}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "data_bucket_pab" {
  bucket = aws_s3_bucket.data_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#tfsec:ignore:aws-s3-encryption-customer-key A customer-managed KMS key costs about $1/month; SSE-S3 keeps this inside the free tier
resource "aws_s3_bucket_server_side_encryption_configuration" "data_bucket_sse" {
  bucket = aws_s3_bucket.data_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "data_bucket_versioning" {
  bucket = aws_s3_bucket.data_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Old versions are kept for 7 days (undo window), then deleted to stay in the free tier
resource "aws_s3_bucket_lifecycle_configuration" "data_bucket_lifecycle" {
  bucket = aws_s3_bucket.data_bucket.id

  rule {
    id     = "expire_old_versions"
    status = "Enabled"
    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 7
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.data_bucket_versioning]
}

# Every request to the data bucket is recorded in the logging bucket
resource "aws_s3_bucket_logging" "data_bucket_logging" {
  bucket        = aws_s3_bucket.data_bucket.id
  target_bucket = aws_s3_bucket.logging_bucket.id
  target_prefix = "s3-access-logs/data/"

  depends_on = [aws_s3_bucket_policy.logging_bucket_policy]
}

# Browsers may upload directly to S3, but only from our own website
resource "aws_s3_bucket_cors_configuration" "data_bucket_cors" {
  bucket = aws_s3_bucket.data_bucket.id

  cors_rule {
    allowed_methods = ["POST"]
    allowed_origins = ["https://${aws_cloudfront_distribution.site.domain_name}"]
    allowed_headers = ["*"]
    max_age_seconds = 3000
  }
}

resource "aws_s3_bucket_policy" "data_bucket_policy" {
  bucket = aws_s3_bucket.data_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.data_bucket.arn,
          "${aws_s3_bucket.data_bucket.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.data_bucket_pab]
}
