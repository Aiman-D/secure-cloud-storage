# =============================================================================
# Website: private S3 bucket served only through CloudFront (Origin Access
# Control), with HTTPS and strict security headers.
# =============================================================================

locals {
  frontend_dir = "${path.module}/../frontend"

  # Skip hidden files such as macOS .DS_Store
  frontend_files = toset([
    for f in fileset(local.frontend_dir, "**") : f
    if !startswith(basename(f), ".")
  ])

  mime_types = {
    html = "text/html; charset=utf-8"
    css  = "text/css; charset=utf-8"
    js   = "application/javascript; charset=utf-8"
    svg  = "image/svg+xml"
    png  = "image/png"
    ico  = "image/x-icon"
  }

  # Content Security Policy: the page may only talk to Cognito, our API and our data bucket
  csp = join("; ", [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self' https://cognito-idp.${local.region}.amazonaws.com https://*.execute-api.${local.region}.amazonaws.com https://${aws_s3_bucket.data_bucket.bucket}.s3.amazonaws.com https://${aws_s3_bucket.data_bucket.bucket_regional_domain_name}",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ])
}

resource "aws_s3_bucket" "site" {
  bucket        = "${var.project_name}-site-${random_string.suffix.result}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "site_pab" {
  bucket = aws_s3_bucket.site.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#tfsec:ignore:aws-s3-encryption-customer-key A customer-managed KMS key costs about $1/month; SSE-S3 keeps this inside the free tier
resource "aws_s3_bucket_server_side_encryption_configuration" "site_sse" {
  bucket = aws_s3_bucket.site.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "site_versioning" {
  bucket = aws_s3_bucket.site.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "site_lifecycle" {
  bucket = aws_s3_bucket.site.id

  rule {
    id     = "expire_old_versions"
    status = "Enabled"
    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.site_versioning]
}

resource "aws_s3_bucket_logging" "site_logging" {
  bucket        = aws_s3_bucket.site.id
  target_bucket = aws_s3_bucket.logging_bucket.id
  target_prefix = "s3-access-logs/site/"

  depends_on = [aws_s3_bucket_policy.logging_bucket_policy]
}

resource "aws_cloudfront_origin_access_control" "site" {
  name                              = "${var.project_name}-oac"
  description                       = "Lets only CloudFront read the private website bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

locals {
  # AWS-managed "CachingDisabled" policy (same ID in every account), so file updates show instantly
  cache_policy_caching_disabled = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
}

resource "aws_cloudfront_response_headers_policy" "security" {
  name    = "${var.project_name}-security-headers"
  comment = "CSP, HSTS, clickjacking and MIME-sniffing protection"

  security_headers_config {
    content_security_policy {
      content_security_policy = local.csp
      override                = true
    }
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      override                   = true
    }
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
  }
}

#tfsec:ignore:aws-cloudfront-enable-waf AWS WAF costs about $5/month, outside the free tier; API Gateway throttling and Cognito auth protect the backend
#tfsec:ignore:aws-cloudfront-enable-logging Standard CloudFront logs need an ACL-enabled bucket; S3 access logs and CloudWatch cover this project
#tfsec:ignore:aws-cloudfront-use-secure-tls-policy The default *.cloudfront.net certificate does not allow choosing the TLS policy; a custom domain would fix this
resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  comment             = "${var.project_name} web app"
  default_root_object = "index.html"
  price_class         = "PriceClass_100"
  http_version        = "http2and3"

  origin {
    domain_name              = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id                = "site-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.site.id
  }

  default_cache_behavior {
    target_origin_id           = "site-s3"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    compress                   = true
    cache_policy_id            = local.cache_policy_caching_disabled
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudFrontOnly"
        Effect    = "Allow"
        Principal = { Service = "cloudfront.amazonaws.com" }
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.site.arn}/*"
        Condition = {
          StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.site.arn }
        }
      },
      {
        Sid       = "EnforceHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.site.arn,
          "${aws_s3_bucket.site.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.site_pab]
}

# -----------------------------------------------------------------------------
# Website files
# -----------------------------------------------------------------------------
resource "aws_s3_object" "frontend" {
  for_each = local.frontend_files

  bucket       = aws_s3_bucket.site.id
  key          = each.value
  source       = "${local.frontend_dir}/${each.value}"
  etag         = filemd5("${local.frontend_dir}/${each.value}")
  content_type = lookup(local.mime_types, lower(reverse(split(".", each.value))[0]), "application/octet-stream")

  depends_on = [aws_s3_bucket_server_side_encryption_configuration.site_sse]
}

# Settings the website needs, generated from the real resource IDs
resource "aws_s3_object" "config" {
  bucket       = aws_s3_bucket.site.id
  key          = "config.js"
  content_type = "application/javascript; charset=utf-8"
  content = "window.APP_CONFIG = ${jsonencode({
    region           = local.region
    userPoolClientId = aws_cognito_user_pool_client.web.id
    apiUrl           = trimsuffix(aws_apigatewayv2_stage.default.invoke_url, "/")
    maxUploadMb      = var.max_upload_mb
    services = [
      "S3", "CloudFront", "Cognito", "API Gateway", "Lambda", "IAM", "STS",
      "CloudTrail", "EventBridge", "SNS", "CloudWatch", "X-Ray",
      "IAM Access Analyzer", "S3 Storage Lens"
    ]
  })};\n"

  depends_on = [aws_s3_bucket_server_side_encryption_configuration.site_sse]
}
