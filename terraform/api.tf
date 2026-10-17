# =============================================================================
# File API: API Gateway (HTTP API) + Cognito JWT authorizer + Lambda.
# The browser never gets AWS keys; it only gets short-lived S3 links.
# =============================================================================

locals {
  api_lambda_name = "${var.project_name}-api"
  api_routes = [
    "GET /files",
    "POST /upload-url",
    "GET /download-url",
    "DELETE /files",
    "GET /status"
  ]
}

data "archive_file" "api_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/api/api.py"
  output_path = "${path.module}/build/api.zip"
}

#tfsec:ignore:aws-cloudwatch-log-group-customer-key A customer-managed KMS key costs about $1/month; CloudWatch Logs are encrypted with AWS-managed keys by default
resource "aws_cloudwatch_log_group" "api_lambda" {
  name              = "/aws/lambda/${local.api_lambda_name}"
  retention_in_days = 14
}

resource "aws_iam_role" "api_lambda" {
  name = "${var.project_name}-api-lambda"

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

resource "aws_iam_role_policy" "api_lambda" {
  name = "least-privilege-file-api"
  role = aws_iam_role.api_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "OwnLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.api_lambda.arn}:*"
      },
      {
        Sid      = "ListOnlyUserFolders"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.data_bucket.arn
        Condition = {
          StringLike = { "s3:prefix" = ["users/*"] }
        }
      },
      {
        Sid      = "ReadWriteOnlyUserFolders"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.data_bucket.arn}/users/*"
      },
      {
        Sid    = "ReadSecuritySettings"
        Effect = "Allow"
        Action = [
          "s3:GetBucketPublicAccessBlock",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketVersioning",
          "s3:GetBucketPolicy"
        ]
        Resource = aws_s3_bucket.data_bucket.arn
      },
      {
        Sid    = "ReadRemediationHistory"
        Effect = "Allow"
        Action = ["logs:DescribeLogStreams", "logs:GetLogEvents"]
        Resource = [
          local.remediator_log_arn,
          "${local.remediator_log_arn}:*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "api_lambda_xray" {
  role       = aws_iam_role.api_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_lambda_function" "api" {
  filename         = data.archive_file.api_zip.output_path
  function_name    = local.api_lambda_name
  description      = "File API for the website: list, upload links, download links, delete, security status"
  role             = aws_iam_role.api_lambda.arn
  handler          = "api.handler"
  runtime          = "python3.12"
  timeout          = 10
  memory_size      = 128
  source_code_hash = data.archive_file.api_zip.output_base64sha256

  environment {
    variables = {
      DATA_BUCKET          = aws_s3_bucket.data_bucket.id
      REMEDIATOR_LOG_GROUP = local.remediator_log_group
      MAX_UPLOAD_MB        = tostring(var.max_upload_mb)
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.api_lambda]
}

resource "aws_apigatewayv2_api" "main" {
  name          = "${var.project_name}-api"
  protocol_type = "HTTP"
  description   = "File API for the secure storage website"

  cors_configuration {
    allow_origins = ["https://${aws_cloudfront_distribution.site.domain_name}"]
    allow_methods = ["GET", "POST", "DELETE", "OPTIONS"]
    allow_headers = ["authorization", "content-type"]
    max_age       = 3600
  }
}

resource "aws_apigatewayv2_authorizer" "cognito" {
  api_id           = aws_apigatewayv2_api.main.id
  name             = "cognito-jwt"
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.web.id]
    issuer   = "https://${aws_cognito_user_pool.main.endpoint}"
  }
}

resource "aws_apigatewayv2_integration" "api" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "routes" {
  for_each = toset(local.api_routes)

  api_id             = aws_apigatewayv2_api.main.id
  route_key          = each.value
  target             = "integrations/${aws_apigatewayv2_integration.api.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

#tfsec:ignore:aws-cloudwatch-log-group-customer-key A customer-managed KMS key costs about $1/month; CloudWatch Logs are encrypted with AWS-managed keys by default
resource "aws_cloudwatch_log_group" "api_access" {
  name              = "/aws/apigateway/${var.project_name}"
  retention_in_days = 14
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = "$default"
  auto_deploy = true

  # Rate limiting: blunts brute-force and abuse
  default_route_settings {
    throttling_burst_limit = 20
    throttling_rate_limit  = 10
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access.arn
    format = jsonencode({
      time      = "$context.requestTime"
      requestId = "$context.requestId"
      sourceIp  = "$context.identity.sourceIp"
      userId    = "$context.authorizer.claims.sub"
      route     = "$context.routeKey"
      status    = "$context.status"
      latencyMs = "$context.responseLatency"
      authError = "$context.authorizer.error"
    })
  }
}

resource "aws_lambda_permission" "allow_api_gateway" {
  statement_id  = "AllowExecutionFromApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}
