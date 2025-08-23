# =============================================================================
# StartupCo AWS Security - Variables Definition
# =============================================================================
# This file defines all input variables used in the Terraform configuration.
# Variables allow you to customize the deployment without modifying main.tf
# =============================================================================

# -----------------------------------------------------------------------------
# GENERAL CONFIGURATION VARIABLES
# -----------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region where resources will be created"
  type        = string
  default     = "ap-northeast-1"
  
  validation {
    condition = can(regex("^[a-z0-9-]+$", var.aws_region))
    error_message = "The aws_region must be a valid AWS region name."
  }
}

variable "company_name" {
  description = "Company name used for resource naming and tagging"
  type        = string
  default     = "startup-co"
  
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.company_name))
    error_message = "Company name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

# -----------------------------------------------------------------------------
# IAM PASSWORD POLICY VARIABLES
# -----------------------------------------------------------------------------

variable "password_min_length" {
  description = "Minimum length for user passwords"
  type        = number
  default     = 14
  
  validation {
    condition     = var.password_min_length >= 8 && var.password_min_length <= 128
    error_message = "Password minimum length must be between 8 and 128 characters."
  }
}

variable "password_max_age" {
  description = "Maximum age for passwords in days (0 means no expiration)"
  type        = number
  default     = 90
  
  validation {
    condition     = var.password_max_age >= 0 && var.password_max_age <= 1095
    error_message = "Password max age must be between 0 and 1095 days."
  }
}

variable "password_reuse_prevention" {
  description = "Number of previous passwords to prevent reuse"
  type        = number
  default     = 12
  
  validation {
    condition     = var.password_reuse_prevention >= 0 && var.password_reuse_prevention <= 24
    error_message = "Password reuse prevention must be between 0 and 24."
  }
}

# -----------------------------------------------------------------------------
# TEAM SIZE VARIABLES
# -----------------------------------------------------------------------------

variable "developer_count" {
  description = "Number of developer users to create"
  type        = number
  default     = 4
  
  validation {
    condition     = var.developer_count >= 0 && var.developer_count <= 20
    error_message = "Developer count must be between 0 and 20."
  }
}

variable "operations_count" {
  description = "Number of operations team users to create"
  type        = number
  default     = 2
  
  validation {
    condition     = var.operations_count >= 0 && var.operations_count <= 10
    error_message = "Operations count must be between 0 and 10."
  }
}

variable "analyst_count" {
  description = "Number of data analyst users to create"
  type        = number
  default     = 3
  
  validation {
    condition     = var.analyst_count >= 0 && var.analyst_count <= 15
    error_message = "Analyst count must be between 0 and 15."
  }
}

variable "finance_users_enabled" {
  description = "Whether to create finance users (true/false)"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# SECURITY AND MONITORING VARIABLES
# -----------------------------------------------------------------------------

variable "enable_guardduty" {
  description = "Whether to enable Amazon GuardDuty threat detection"
  type        = bool
  default     = false  # Will enable in Phase 3 of implementation
}

variable "enable_config" {
  description = "Whether to enable AWS Config for compliance monitoring"
  type        = bool
  default     = false  # Will enable in advanced phases
}

variable "cloudtrail_log_retention_days" {
  description = "Number of days to retain CloudTrail logs in CloudWatch"
  type        = number
  default     = 90
  
  validation {
    condition     = var.cloudtrail_log_retention_days >= 1 && var.cloudtrail_log_retention_days <= 3653
    error_message = "CloudTrail log retention must be between 1 and 3653 days (10 years)."
  }
}

variable "failed_login_threshold" {
  description = "Number of failed login attempts before triggering alarm"
  type        = number
  default     = 3
  
  validation {
    condition     = var.failed_login_threshold >= 1 && var.failed_login_threshold <= 10
    error_message = "Failed login threshold must be between 1 and 10."
  }
}

# -----------------------------------------------------------------------------
# NOTIFICATION VARIABLES
# -----------------------------------------------------------------------------

variable "security_alert_email" {
  description = "Email address to receive security alerts (optional)"
  type        = string
  default     = ""
  
  validation {
    condition = var.security_alert_email == "" || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.security_alert_email))
    error_message = "Please provide a valid email address or leave empty."
  }
}

variable "security_alert_phone" {
  description = "Phone number for SMS security alerts (format: +1234567890)"
  type        = string
  default     = ""
  
  validation {
    condition = var.security_alert_phone == "" || can(regex("^\\+[1-9]\\d{1,14}$", var.security_alert_phone))
    error_message = "Phone number must be in international format (+1234567890) or leave empty."
  }
}

# -----------------------------------------------------------------------------
# COST CONTROL VARIABLES
# -----------------------------------------------------------------------------

variable "monthly_budget_alert_threshold" {
  description = "Monthly budget threshold in USD for cost alerts"
  type        = number
  default     = 500
  
  validation {
    condition     = var.monthly_budget_alert_threshold >= 1
    error_message = "Budget threshold must be at least $1."
  }
}

variable "s3_lifecycle_transition_days" {
  description = "Number of days before S3 objects transition to cheaper storage"
  type        = number
  default     = 30
  
  validation {
    condition     = var.s3_lifecycle_transition_days >= 1
    error_message = "S3 lifecycle transition days must be at least 1."
  }
}

# -----------------------------------------------------------------------------
# RESOURCE NAMING VARIABLES
# -----------------------------------------------------------------------------

variable "resource_tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default = {
    Owner       = "StartupCo"
    Purpose     = "Security"
    Compliance  = "Required"
  }
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection for critical resources"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# ADVANCED SECURITY VARIABLES (Future Use)
# -----------------------------------------------------------------------------

variable "enable_vpc_flow_logs" {
  description = "Whether to enable VPC Flow Logs"
  type        = bool
  default     = false  # Will enable in advanced phases
}

variable "enable_security_hub" {
  description = "Whether to enable AWS Security Hub"
  type        = bool
  default     = false  # Will enable in advanced phases
}

variable "compliance_frameworks" {
  description = "List of compliance frameworks to enable (e.g., CIS, PCI-DSS)"
  type        = list(string)
  default     = []  # Will populate in advanced phases
}

# -----------------------------------------------------------------------------
# VALIDATION HELPERS
# -----------------------------------------------------------------------------

locals {
  # Calculate total number of users that will be created
  total_users = var.developer_count + var.operations_count + var.analyst_count + (var.finance_users_enabled ? 1 : 0)
  
  # Validate we're not creating too many users
  validate_user_count = local.total_users <= 50 ? true : tobool("Total user count cannot exceed 50")
  
  # Common naming prefix for all resources
  name_prefix = "${var.company_name}-${var.environment}"
  
  # Standard tags that will be applied to all resources
  standard_tags = merge(var.resource_tags, {
    Environment   = var.environment
    Project      = "${var.company_name}-security"
    ManagedBy    = "terraform"
    CreatedDate  = formatdate("YYYY-MM-DD", timestamp())
  })
}