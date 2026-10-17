output "website_url" {
  description = "Open this in a browser (CloudFront can take 5-10 minutes to go live after the first deploy)"
  value       = "https://${aws_cloudfront_distribution.site.domain_name}"
}

output "website_username" {
  value = var.demo_username
}

output "api_url" {
  value = trimsuffix(aws_apigatewayv2_stage.default.invoke_url, "/")
}

output "dashboard_url" {
  value = "https://${local.region}.console.aws.amazon.com/cloudwatch/home?region=${local.region}#dashboards/dashboard/${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "data_bucket_name" {
  value = aws_s3_bucket.data_bucket.id
}

output "logging_bucket_name" {
  value = aws_s3_bucket.logging_bucket.id
}

output "application_role_arn" {
  value = aws_iam_role.app_role.arn
}

output "security_auditor_role_arn" {
  value = aws_iam_role.security_auditor_role.arn
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "cognito_user_pool_id" {
  value = aws_cognito_user_pool.main.id
}
