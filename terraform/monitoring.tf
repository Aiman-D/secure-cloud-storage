# =============================================================================
# Monitoring: CloudTrail, CloudWatch alarms and dashboard, Access Analyzer,
# Storage Lens, and optional GuardDuty
# =============================================================================

# -----------------------------------------------------------------------------
# CloudTrail: records every management API call, to S3 and to CloudWatch Logs
# -----------------------------------------------------------------------------
#tfsec:ignore:aws-cloudwatch-log-group-customer-key A customer-managed KMS key costs about $1/month; CloudWatch Logs are encrypted with AWS-managed keys by default
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.project_name}"
  retention_in_days = 14
}

resource "aws_iam_role" "cloudtrail_to_cloudwatch" {
  name = "${var.project_name}-cloudtrail-cw"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_to_cloudwatch" {
  name = "write-cloudtrail-logs"
  role = aws_iam_role.cloudtrail_to_cloudwatch.id

  #tfsec:ignore:aws-iam-no-policy-wildcards CloudTrail names its log streams itself; the wildcard only covers streams inside this one log group
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}

#tfsec:ignore:aws-cloudtrail-enable-at-rest-encryption A customer-managed KMS key costs about $1/month; the log bucket uses SSE-S3 encryption instead
resource "aws_cloudtrail" "main" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.logging_bucket.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  # Management events only (free); data events are not recorded
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cloudwatch.arn

  depends_on = [
    aws_s3_bucket_policy.logging_bucket_policy,
    aws_iam_role_policy.cloudtrail_to_cloudwatch
  ]
}

# -----------------------------------------------------------------------------
# CloudWatch alarms (CIS benchmark style), all emailing the SNS topic
# -----------------------------------------------------------------------------
locals {
  security_metric_namespace = "${var.project_name}/Security"

  security_alarms = {
    root-account-usage = {
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      metric      = "RootAccountUsage"
      description = "The root user was used. Root should be locked away and almost never used."
    }
    console-login-failures = {
      pattern     = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
      metric      = "ConsoleLoginFailures"
      description = "Someone failed to sign in to the AWS console."
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "security" {
  for_each = local.security_alarms

  name           = "${var.project_name}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.value.metric
    namespace = local.security_metric_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security" {
  for_each = local.security_alarms

  alarm_name          = "${var.project_name}-${each.key}"
  alarm_description   = each.value.description
  namespace           = local.security_metric_namespace
  metric_name         = each.value.metric
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.security]
}

resource "aws_cloudwatch_metric_alarm" "remediator_errors" {
  alarm_name          = "${var.project_name}-remediator-errors"
  alarm_description   = "The auto-remediation Lambda failed, so a bucket may be left unprotected."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.remediator.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# -----------------------------------------------------------------------------
# CloudWatch dashboard: one screen for the whole system
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.project_name}-security"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Auto-remediation Lambda"
          region = local.region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.remediator.function_name],
            [".", "Errors", ".", "."]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Website API traffic"
          region = local.region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/ApiGateway", "Count", "ApiId", aws_apigatewayv2_api.main.id],
            [".", "4xx", ".", "."],
            [".", "5xx", ".", "."]
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Security events (from CloudTrail)"
          region = local.region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            [local.security_metric_namespace, "RootAccountUsage"],
            [".", "ConsoleLoginFailures"]
          ]
        }
      },
      {
        type   = "log"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Recent auto-fixes"
          region = local.region
          view   = "table"
          query  = "SOURCE '${local.remediator_log_group}' | fields @timestamp, @message | filter @message like /Remediation successful/ | sort @timestamp desc | limit 20"
        }
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# IAM Access Analyzer: flags anything shared outside the account (free)
# -----------------------------------------------------------------------------
resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = "${var.project_name}-analyzer"
  type          = "ACCOUNT"
}

# -----------------------------------------------------------------------------
# S3 Storage Lens: free-tier storage dashboard (data appears within 48 hours)
# -----------------------------------------------------------------------------
resource "aws_s3control_storage_lens_configuration" "main" {
  config_id  = "${var.project_name}-lens"
  account_id = local.account_id

  storage_lens_configuration {
    enabled = true

    account_level {
      activity_metrics {
        enabled = false # advanced metrics cost extra
      }
      bucket_level {
        activity_metrics {
          enabled = false
        }
      }
    }
  }
}

# -----------------------------------------------------------------------------
# GuardDuty (optional): threat detection. 30-day free trial, so off by default.
# -----------------------------------------------------------------------------
resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true
}
