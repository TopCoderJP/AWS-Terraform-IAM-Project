# =============================================================================
# StartupCo AWS IAM Security Implementation with Terraform
# =============================================================================
# This Terraform configuration implements a comprehensive IAM security solution
# for StartupCo's AWS infrastructure, following AWS best practices and the
# principle of least privilege.
#
# =============================================================================

# -----------------------------------------------------------------------------
# TERRAFORM CONFIGURATION
# -----------------------------------------------------------------------------
# Specifying the required Terraform version and AWS provider version
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
  }
}

# Configuring the AWS provider with my desired region
provider "aws" {
  region = var.aws_region
  
  # Default tags that will be applied to all resources
  default_tags {
    tags = {
      Environment = "production"
      Project     = "startup-co-security"
      ManagedBy   = "terraform"
      Team        = "platform"
    }
  }
}

# -----------------------------------------------------------------------------
# DATA SOURCES
# -----------------------------------------------------------------------------
# Getting current AWS account information
data "aws_caller_identity" "current" {}

# Getting available availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# -----------------------------------------------------------------------------
# RANDOM RESOURCES FOR UNIQUE NAMING
# -----------------------------------------------------------------------------
# Generate a random string for unique bucket naming
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# -----------------------------------------------------------------------------
# STEP 1: SECURING THE ROOT ACCOUNT
# -----------------------------------------------------------------------------
# IMPORTANT: The following settings require manual configuration in my AWS Console
# as Terraform cannot directly manage root account MFA settings

# Creaing an S3 bucket for storing important account information securely
resource "aws_s3_bucket" "account_security" {
  bucket = "${var.company_name}-account-security-${random_string.bucket_suffix.result}"
  
  tags = {
    Name        = "Account Security Storage"
    Description = "Secure storage for account security information"
  }
}

# Enabling versioning to track changes to security documents
resource "aws_s3_bucket_versioning" "account_security_versioning" {
  bucket = aws_s3_bucket.account_security.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enabling server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "account_security_encryption" {
  bucket = aws_s3_bucket.account_security.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Blocking all public access - this S3 bucket should never be public, so I've blocked it from public access 
resource "aws_s3_bucket_public_access_block" "account_security_pab" {
  bucket = aws_s3_bucket.account_security.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Creating a CloudTrail for auditing root account usage
resource "aws_cloudtrail" "root_account_audit" {
  name                          = "${var.company_name}-root-account-audit"
  s3_bucket_name               = aws_s3_bucket.account_security.bucket
  s3_key_prefix               = "cloudtrail-logs/"
  include_global_service_events = true
  is_multi_region_trail        = true
  enable_logging               = true
  
  # Enabling log file validation for integrity
  enable_log_file_validation = true
  
  # Configuring event selector to capture management events
  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    exclude_management_event_sources = []
  }
  
  tags = {
    Name        = "Root Account Audit Trail"
    Description = "Audit trail for root account activity monitoring"
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_bucket_policy]
}

# S3 bucket policy for CloudTrail
resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.account_security.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.account_security.arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${var.company_name}-root-account-audit"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.account_security.arn}/cloudtrail-logs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "AWS:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${var.company_name}-root-account-audit"
          }
        }
      }
    ]
  })
}

# Creating an SNS topic for security alerts
resource "aws_sns_topic" "security_alerts" {
  name = "${var.company_name}-security-alerts"
  
  tags = {
    Name        = "Security Alerts"
    Description = "SNS topic for security-related alerts"
  }
}

# Creating a CloudWatch alarm for root account usage
resource "aws_cloudwatch_log_group" "cloudtrail_log_group" {
  name              = "/aws/cloudtrail/${var.company_name}"
  retention_in_days = 90

  tags = {
    Name = "CloudTrail Log Group"
  }
}

resource "aws_cloudwatch_log_stream" "cloudtrail_log_stream" {
  name           = "${var.company_name}-cloudtrail-stream"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_log_group.name
}

resource "aws_cloudwatch_metric_alarm" "root_account_usage" {
  alarm_name          = "${var.company_name}-root-account-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootAccountUsage"
  namespace           = "CWLogs"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors root account usage"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  
  tags = {
    Name        = "Root Account Usage Alarm"
    Description = "Alert when root account is used"
  }
}

# -----------------------------------------------------------------------------
# STEP 2: CREATING IAM PASSWORD POLICY
# -----------------------------------------------------------------------------
# Implementing a strong password policy that enforces security best practices
resource "aws_iam_account_password_policy" "strict_password_policy" {
  # Password complexity requirements
  minimum_password_length        = var.password_min_length
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers               = true
  require_symbols               = true
  
  # Password rotation and reuse policies
  max_password_age              = var.password_max_age
  password_reuse_prevention     = 12  # Prevent reuse of last 12 passwords
  
  # User password management
  allow_users_to_change_password = true
  hard_expiry                   = false  # Allow grace period for password change
}

# -----------------------------------------------------------------------------
# STEP 3: CREATING IAM GROUPS WITH SPECIFIC PERMISSIONS
# -----------------------------------------------------------------------------

# Group 1: Developers Group
# Developers need access to EC2, S3, and CloudWatch for application development
resource "aws_iam_group" "developers" {
  name = "${var.company_name}-developers"
  path = "/teams/"
}

# Developer group policy - EC2 management permissions
resource "aws_iam_group_policy" "developers_ec2" {
  name  = "${var.company_name}-developers-ec2-policy"
  group = aws_iam_group.developers.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # EC2 instance management permissions
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages",
          "ec2:DescribeKeyPairs",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:RebootInstances",
          "ec2:CreateTags",
          "ec2:DescribeTags"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      },
      {
        # CloudWatch Logs viewing permissions
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:GetLogEvents",
          "logs:FilterLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# Developer group policy - S3 application files access
resource "aws_iam_group_policy" "developers_s3" {
  name  = "${var.company_name}-developers-s3-policy"
  group = aws_iam_group.developers.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # S3 bucket listing permissions
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning"
        ]
        Resource = [
          "arn:aws:s3:::${var.company_name}-app-assets*",
          "arn:aws:s3:::${var.company_name}-application-logs*"
        ]
      },
      {
        # S3 object management permissions for application files
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:GetObjectVersion",
          "s3:PutObjectAcl"
        ]
        Resource = [
          "arn:aws:s3:::${var.company_name}-app-assets*/*",
          "arn:aws:s3:::${var.company_name}-application-logs*/*"
        ]
      }
    ]
  })
}

# Group 2: Operations (Team) Group
# Operations team needs full infrastructure access for system management
resource "aws_iam_group" "operations" {
  name = "${var.company_name}-operations"
  path = "/teams/"
}

# Operations group policy - Full infrastructure access
resource "aws_iam_group_policy" "operations_full_access" {
  name  = "${var.company_name}-operations-full-policy"
  group = aws_iam_group.operations.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Full EC2 management permissions
        Effect = "Allow"
        Action = [
          "ec2:*",
          "vpc:*",
          "elasticloadbalancing:*",
          "autoscaling:*"
        ]
        Resource = "*"
      },
      {
        # Full CloudWatch permissions
        Effect = "Allow"
        Action = [
          "cloudwatch:*",
          "logs:*"
        ]
        Resource = "*"
      },
      {
        # Systems Manager permissions for server management
        Effect = "Allow"
        Action = [
          "ssm:*",
          "ssmmessages:*",
          "ec2messages:*"
        ]
        Resource = "*"
      },
      {
        # RDS management permissions
        Effect = "Allow"
        Action = [
          "rds:*"
        ]
        Resource = "*"
      },
      {
        # S3 management permissions
        Effect = "Allow"
        Action = [
          "s3:*"
        ]
        Resource = "*"
      }
    ]
  })
}

# Group 3: Finance Group
# Finance team needs cost management and read-only resource access
resource "aws_iam_group" "finance" {
  name = "${var.company_name}-finance"
  path = "/teams/"
}

# Finance group policy - Cost management and read-only access
resource "aws_iam_group_policy" "finance_cost_management" {
  name  = "${var.company_name}-finance-cost-policy"
  group = aws_iam_group.finance.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Cost Explorer and billing permissions
        Effect = "Allow"
        Action = [
          "ce:*",
          "budgets:*",
          "aws-portal:ViewBilling",
          "aws-portal:ViewAccount",
          "aws-portal:ViewUsage",
          "cur:DescribeReportDefinitions",
          "cur:PutReportDefinition",
          "cur:DeleteReportDefinition",
          "cur:ModifyReportDefinition"
        ]
        Resource = "*"
      },
      {
        # Read-only access to AWS resources for cost analysis
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "rds:Describe*",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning",
          "s3:ListBucket",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "cloudwatch:Describe*"
        ]
        Resource = "*"
      }
    ]
  })
}

# Group 4: Data Analysts Group
# Analysts need read-only access to data resources
resource "aws_iam_group" "analysts" {
  name = "${var.company_name}-analysts"
  path = "/teams/"
}

# Analysts group policy - Read-only data access
resource "aws_iam_group_policy" "analysts_data_access" {
  name  = "${var.company_name}-analysts-data-policy"
  group = aws_iam_group.analysts.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Read-only S3 access for data analysis
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetObjectVersion"
        ]
        Resource = [
          "arn:aws:s3:::${var.company_name}-user-data*",
          "arn:aws:s3:::${var.company_name}-user-data*/*",
          "arn:aws:s3:::${var.company_name}-analytics-data*",
          "arn:aws:s3:::${var.company_name}-analytics-data*/*"
        ]
      },
      {
        # Read-only RDS access for database queries
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters",
          "rds:DescribeDBSnapshots"
        ]
        Resource = "*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# STEP 4: CREATING IAM USERS
# -----------------------------------------------------------------------------

# Creating users for the development team
resource "aws_iam_user" "developers" {
  count = var.developer_count
  name  = "${var.company_name}-dev-${count.index + 1}"
  path  = "/teams/developers/"
  
  # Forcing users to create a new password on first login
  force_destroy = true
  
  tags = {
    Team        = "Development"
    UserType    = "Developer"
    CreatedBy   = "Terraform"
  }
}

# Adding developers to the developers group
resource "aws_iam_group_membership" "developers" {
  name = "${var.company_name}-developers-membership"
  users = aws_iam_user.developers[*].name
  group = aws_iam_group.developers.name
}

# Creating users for the operations team
resource "aws_iam_user" "operations" {
  count = var.operations_count
  name  = "${var.company_name}-ops-${count.index + 1}"
  path  = "/teams/operations/"
  
  force_destroy = true
  
  tags = {
    Team        = "Operations"
    UserType    = "Operations"
    CreatedBy   = "Terraform"
  }
}

# Adding operations users to the operations group
resource "aws_iam_group_membership" "operations" {
  name = "${var.company_name}-operations-membership"
  users = aws_iam_user.operations[*].name
  group = aws_iam_group.operations.name
}

# Creating user for the finance manager
resource "aws_iam_user" "finance" {
  name = "${var.company_name}-finance-manager"
  path = "/teams/finance/"
  
  force_destroy = true
  
  tags = {
    Team        = "Finance"
    UserType    = "Finance Manager"
    CreatedBy   = "Terraform"
  }
}

# Adding finance user to the finance group
resource "aws_iam_group_membership" "finance" {
  name = "${var.company_name}-finance-membership"
  users = [aws_iam_user.finance.name]
  group = aws_iam_group.finance.name
}

# Creating users for the data analysts
resource "aws_iam_user" "analysts" {
  count = var.analyst_count
  name  = "${var.company_name}-analyst-${count.index + 1}"
  path  = "/teams/analysts/"
  
  force_destroy = true
  
  tags = {
    Team        = "Analytics"
    UserType    = "Data Analyst"
    CreatedBy   = "Terraform"
  }
}

# Adding analysts to the analysts group
resource "aws_iam_group_membership" "analysts" {
  name = "${var.company_name}-analysts-membership"
  users = aws_iam_user.analysts[*].name
  group = aws_iam_group.analysts.name
}

# -----------------------------------------------------------------------------
# STEP 5: ENFORCING MFA FOR ALL USERS
# -----------------------------------------------------------------------------

# Creating a policy that requires MFA for all actions
resource "aws_iam_policy" "enforce_mfa" {
  name        = "${var.company_name}-enforce-mfa"
  description = "Policy to enforce MFA for all users"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Allowing users to manage their own MFA devices
        Effect = "Allow"
        Action = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice"
        ]
        Resource = [
          "arn:aws:iam::*:mfa/$${aws:username}",
          "arn:aws:iam::*:user/$${aws:username}"
        ]
      },
      {
        # Allowing users to deactivate their own MFA devices
        Effect = "Allow"
        Action = [
          "iam:DeactivateMFADevice",
          "iam:DeleteVirtualMFADevice"
        ]
        Resource = [
          "arn:aws:iam::*:mfa/$${aws:username}",
          "arn:aws:iam::*:user/$${aws:username}"
        ]
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      },
      {
        # Allowing users to change their own password
        Effect = "Allow"
        Action = [
          "iam:ChangePassword",
          "iam:GetAccountPasswordPolicy"
        ]
        Resource = "*"
      },
      {
        # Denying all other actions without MFA
        Effect = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "iam:ChangePassword",
          "iam:GetAccountPasswordPolicy"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}

# Attaching MFA enforcement policy to all groups
resource "aws_iam_group_policy_attachment" "developers_mfa" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.enforce_mfa.arn
}

resource "aws_iam_group_policy_attachment" "operations_mfa" {
  group      = aws_iam_group.operations.name
  policy_arn = aws_iam_policy.enforce_mfa.arn
}

resource "aws_iam_group_policy_attachment" "finance_mfa" {
  group      = aws_iam_group.finance.name
  policy_arn = aws_iam_policy.enforce_mfa.arn
}

resource "aws_iam_group_policy_attachment" "analysts_mfa" {
  group      = aws_iam_group.analysts.name
  policy_arn = aws_iam_policy.enforce_mfa.arn
}

# -----------------------------------------------------------------------------
# STEP 6: CREATING LOGIN PROFILES WITH TEMPORARY PASSWORDS
# -----------------------------------------------------------------------------

# Creating login profiles for all users with temporary passwords
# Users will be forced to change these on first login
resource "aws_iam_user_login_profile" "developers" {
  count                   = length(aws_iam_user.developers)
  user                    = aws_iam_user.developers[count.index].name
  password_reset_required = true
}

resource "aws_iam_user_login_profile" "operations" {
  count                   = length(aws_iam_user.operations)
  user                    = aws_iam_user.operations[count.index].name
  password_reset_required = true
}

resource "aws_iam_user_login_profile" "finance" {
  user                    = aws_iam_user.finance.name
  password_reset_required = true
}

resource "aws_iam_user_login_profile" "analysts" {
  count                   = length(aws_iam_user.analysts)
  user                    = aws_iam_user.analysts[count.index].name
  password_reset_required = true
}

# -----------------------------------------------------------------------------
# STEP 7: CREATING MONITORING AND ALERTING
# -----------------------------------------------------------------------------

# Creating a CloudWatch dashboard for monitoring IAM activities
resource "aws_cloudwatch_dashboard" "iam_monitoring" {
  dashboard_name = "${var.company_name}-iam-security-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/CloudTrail", "ErrorCount"],
            [".", "ConsoleLogin"],
            [".", "AssumeRole"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "IAM Activity Metrics"
          period  = 300
        }
      }
    ]
  })
}

# Creating CloudWatch alarms for suspicious activities
resource "aws_cloudwatch_metric_alarm" "failed_console_logins" {
  alarm_name          = "${var.company_name}-failed-console-logins"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ConsoleLoginFailures"
  namespace           = "CWLogs"
  period              = "300"
  statistic           = "Sum"
  threshold           = "3"
  alarm_description   = "This metric monitors failed console login attempts"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  
  tags = {
    Name        = "Failed Console Logins"
    Description = "Alert on multiple failed login attempts"
  }
}

# -----------------------------------------------------------------------------
# OUTPUTS
# -----------------------------------------------------------------------------

# Outputting the account ID for reference
output "aws_account_id" {
  description = "AWS Account ID"
  value       = data.aws_caller_identity.current.account_id
}

# Outputting the IAM users created
output "developer_users" {
  description = "Developer IAM users created"
  value       = aws_iam_user.developers[*].name
}

output "operations_users" {
  description = "Operations IAM users created"
  value       = aws_iam_user.operations[*].name
}

output "finance_user" {
  description = "Finance IAM user created"
  value       = aws_iam_user.finance.name
}

output "analyst_users" {
  description = "Analyst IAM users created"
  value       = aws_iam_user.analysts[*].name
}

# Outputting the groups created
output "iam_groups" {
  description = "IAM groups created"
  value = {
    developers = aws_iam_group.developers.name
    operations = aws_iam_group.operations.name
    finance    = aws_iam_group.finance.name
    analysts   = aws_iam_group.analysts.name
  }
}

# Outputting the security bucket name
output "security_bucket" {
  description = "S3 bucket for security information storage"
  value       = aws_s3_bucket.account_security.bucket
}

# Outputting CloudTrail information
output "cloudtrail_name" {
  description = "CloudTrail for root account monitoring"
  value       = aws_cloudtrail.root_account_audit.name
}

# Outputting SNS topic for alerts
output "security_alerts_topic" {
  description = "SNS topic for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

# -----------------------------------------------------------------------------
# LOCALS FOR REUSABLE VALUES
# -----------------------------------------------------------------------------

locals {
  # Common tags for all resources
  common_tags = {
    Environment = "production"
    Project     = "startup-co-security"
    ManagedBy   = "terraform"
    Team        = "platform"
  }
  
  # Account ID for ARN construction
  account_id = data.aws_caller_identity.current.account_id
  
  # Region for resource naming
  region = var.aws_region
}