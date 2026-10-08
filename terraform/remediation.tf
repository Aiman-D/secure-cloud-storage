data "archive_file" "remediate_zip" {
  type        = "zip"
  source_file = "${path.module}/modules/remediation/src/remediate.py"
  output_path = "${path.module}/modules/remediation/src/remediate.zip"
}

resource "aws_iam_role" "lambda_remediation_role" {
  name = "${var.project_name}-lambda-remediation"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_remediation_policy" {
  name        = "${var.project_name}-lambda-policy"
  description = "Permissions for remediation lambda to modify S3 and log"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_remediation_attach" {
  role       = aws_iam_role.lambda_remediation_role.name
  policy_arn = aws_iam_policy.lambda_remediation_policy.arn
}

resource "aws_lambda_function" "remediator" {
  filename         = data.archive_file.remediate_zip.output_path
  function_name    = "${var.project_name}-s3-remediator"
  role             = aws_iam_role.lambda_remediation_role.arn
  handler          = "remediate.lambda_handler"
  runtime          = "python3.10"
  source_code_hash = data.archive_file.remediate_zip.output_base64sha256
}

resource "aws_cloudwatch_event_rule" "s3_security_event" {
  name        = "${var.project_name}-s3-security-event"
  description = "Triggers on S3 bucket policy or ACL changes"

  event_pattern = jsonencode({
    source = ["aws.s3"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["PutBucketPublicAccessBlock", "PutBucketPolicy", "PutBucketAcl"]
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
