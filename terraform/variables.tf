variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name used for naming and tagging every resource"
  type        = string
  default     = "secure-cloud-storage"
}

variable "alert_email" {
  description = "Email address that receives security alerts. AWS sends a confirmation email you must click first."
  type        = string
}

variable "demo_username" {
  description = "Username for the website login"
  type        = string
  default     = "demo"
}

variable "demo_password" {
  description = "Password for the website login: at least 8 characters with upper case, lower case, a number and a symbol"
  type        = string
  sensitive   = true

  validation {
    condition = (
      length(var.demo_password) >= 8 &&
      can(regex("[A-Z]", var.demo_password)) &&
      can(regex("[a-z]", var.demo_password)) &&
      can(regex("[0-9]", var.demo_password)) &&
      can(regex("[^A-Za-z0-9]", var.demo_password))
    )
    error_message = "demo_password needs 8+ characters with an upper case letter, a lower case letter, a number and a symbol."
  }
}

variable "max_upload_mb" {
  description = "Largest file the website allows, in MB (enforced by S3 itself, not just the browser)"
  type        = number
  default     = 10
}

variable "enable_guardduty" {
  description = "Turn on GuardDuty threat detection. It is a 30-day free trial, so only enable it around the demo."
  type        = bool
  default     = false
}
