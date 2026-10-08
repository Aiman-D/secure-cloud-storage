output "data_bucket_name" {
  value = aws_s3_bucket.data_bucket.id
}

output "logging_bucket_name" {
  value = aws_s3_bucket.logging_bucket.id
}

output "application_role_arn" {
  value = aws_iam_role.app_role.arn
}

output "security_admin_role_arn" {
  value = aws_iam_role.security_admin_role.arn
}
