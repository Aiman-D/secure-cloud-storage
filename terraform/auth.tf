# =============================================================================
# Cognito: website login. No public sign-up; only accounts an admin creates.
# =============================================================================

resource "aws_cognito_user_pool" "main" {
  name                = "${var.project_name}-users"
  deletion_protection = "INACTIVE"

  username_configuration {
    case_sensitive = false
  }

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  password_policy {
    minimum_length                   = 8
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 3
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "admin_only"
      priority = 1
    }
  }
}

resource "aws_cognito_user_pool_client" "web" {
  name         = "${var.project_name}-web"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret               = false # browser apps cannot keep a secret
  explicit_auth_flows           = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
  prevent_user_existence_errors = "ENABLED"

  id_token_validity      = 60
  access_token_validity  = 60
  refresh_token_validity = 1

  token_validity_units {
    id_token      = "minutes"
    access_token  = "minutes"
    refresh_token = "days"
  }
}

resource "aws_cognito_user" "demo" {
  user_pool_id   = aws_cognito_user_pool.main.id
  username       = var.demo_username
  password       = var.demo_password
  message_action = "SUPPRESS"
}
