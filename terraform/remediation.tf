# =============================================================================
# Automated remediation: CloudTrail -> EventBridge -> Lambda -> SNS
# If anyone weakens a bucket's public access settings, the Lambda turns
# Block Public Access back on and emails an alert.
# =============================================================================

locals {
  remediator_name      = "${var.project_name}-s3-remediator"
  remediator_log_group = "/aws/lambda/${local.remediator_name}"
  remediator_log_arn   = "arn:aws:logs:${local.region}:${local.account_id}:log-group:${local.remediator_log_group}"
}

data "archive_file" "remediate_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/remediator/remediate.py"
  output_path = "${path.module}/build/remediator.zip"
}

resource "aws_iam_role" "lambda_remediation_role" {
  name = "${var.project_name}-lambda-remediation"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_remediation_policy" {
  name        = "${var.project_name}-lambda-policy"
  description = "Lets the remediation Lambda read and re-apply S3 Block Public Access, write its logs and send alerts"

  #tfsec:ignore:aws-iam-no-policy-wildcards The guardrail must be able to re-lock any bucket in the account, and it can only change public access settings
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "OwnLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = [
          local.remediator_log_arn,
          "${local.remediator_log_arn}:*"
        ]
      },
      {
        Sid      = "PublicAccessBlockOnly"
        Effect   = "Allow"
        Action   = ["s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock"]
        Resource = "arn:aws:s3:::*"
      },
      {
        Sid      = "SendAlerts"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_remediation_attach" {
  role       = aws_iam_role.lambda_remediation_role.name
  policy_arn = aws_iam_policy.lambda_remediation_policy.arn
}

resource "aws_iam_role_policy_attachment" "lambda_remediation_xray" {
  role       = aws_iam_role.lambda_remediation_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_lambda_function" "remediator" {
  filename         = data.archive_file.remediate_zip.output_path
  function_name    = local.remediator_name
  description      = "Re-enables S3 Block Public Access whenever it is weakened"
  role             = aws_iam_role.lambda_remediation_role.arn
  handler          = "remediate.lambda_handler"
  runtime          = "python3.12"
  timeout          = 15
  source_code_hash = data.archive_file.remediate_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN   = aws_sns_topic.alerts.arn
      OWN_ROLE_MARKER = aws_iam_role.lambda_remediation_role.name
    }
  }

  tracing_config {
    mode = "Active"
  }
}

resource "aws_cloudwatch_event_rule" "s3_security_event" {
  name        = "${var.project_name}-s3-security-event"
  description = "Fires when a bucket's public access settings, policy or ACL change"

  event_pattern = jsonencode({
    source        = ["aws.s3"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
        "PutBucketPolicy",
        "PutBucketAcl"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "trigger_remediator" {
  rule      = aws_cloudwatch_event_rule.s3_security_event.name
  target_id = "TriggerLambdaRemediator"
  arn       = aws_lambda_function.remediator.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_security_event.arn
}
