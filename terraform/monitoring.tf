# -----------------------------------------------------------------------------
# CloudTrail (Management Events - Free Tier)
# -----------------------------------------------------------------------------
resource "aws_cloudtrail" "main" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.logging_bucket.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  
  # By default, CloudTrail only logs Management Events (which is what we want for Free Tier)
  # Data events are not included unless explicitly configured.
  depends_on = [
    aws_s3_bucket_policy.logging_bucket_policy
  ]
}

# -----------------------------------------------------------------------------
# IAM Access Analyzer (Free)
# -----------------------------------------------------------------------------
resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = "${var.project_name}-analyzer"
  type          = "ACCOUNT"
}

# -----------------------------------------------------------------------------
# S3 Storage Lens (Free Tier Dashboard)
# -----------------------------------------------------------------------------
resource "aws_s3control_storage_lens_configuration" "main" {
  config_id = "${var.project_name}-lens"
  account_id = data.aws_caller_identity.current.account_id

  storage_lens_configuration {
    enabled = true

    account_level {
      activity_metrics {
        enabled = false # Activity metrics cost extra, so we leave them disabled for Free Tier
      }
      bucket_level {
        activity_metrics {
          enabled = false
        }
      }
    }
  }
}
