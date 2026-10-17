# =============================================================================
# SNS: security alerts by email
# =============================================================================

#tfsec:ignore:aws-sns-enable-topic-encryption Alerts carry no secrets, and CloudWatch alarms cannot publish to a topic encrypted with the AWS-managed SNS key (a customer key costs about $1/month)
resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-security-alerts"
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
