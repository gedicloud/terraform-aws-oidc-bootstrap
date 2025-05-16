# root account provider
provider "aws" {
  region = var.region
}

provider "tfe" {
  token    = var.token
}

locals {
  hcp_terraform_url = "https://app.terraform.io"
  hcp_audience      = "aws.workload.identity"
  breakglass_username = var.tfc_organization_name 
}

# Retrieve the SHA1 fingerprint of the TLS certificate protecting https://app.terraform.io
data "tls_certificate" "provider" {
  url = local.hcp_terraform_url
}

# Member account provider with role assumption
provider "aws" {
  alias  = "member_account"
  region = var.region
  assume_role {
    # Replace ${member_account.this.id} with the actual account ID or a variable reference
    role_arn = "arn:aws:iam::${var.member_account_id}:role/OrganizationAccountAccessRole"
  }
}

resource "aws_iam_openid_connect_provider" "hcp_terraform" {
  provider = aws.member_account  # Corrected from aws.member_account_id
  url      = local.hcp_terraform_url

  client_id_list = [
    local.hcp_audience,
  ]

  thumbprint_list = [
    data.tls_certificate.provider.certificates[0].sha1_fingerprint,
  ]
}

data "aws_iam_policy_document" "hcp_oidc_assume_role_policy" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.hcp_terraform.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "app.terraform.io:aud"
      values   = [local.hcp_audience]
    }
    condition {
      test     = "StringLike"
      variable = "app.terraform.io:sub"
      values   = ["organization:${var.tfc_organization_name}:*"]
    }
  }
}

# IAM role in the member account that can be assumed by HCP Terraform
resource "aws_iam_role" "this" {
  provider           = aws.member_account
  name               = "tfc-oidc-role"
  assume_role_policy = data.aws_iam_policy_document.hcp_oidc_assume_role_policy.json
}

# Allow the tfc-oidc-role to assume the Route53 delegation role in platform account
resource "aws_iam_role_policy" "allow_crossaccount_route53" {
  provider = aws.member_account
  name     = "AllowRoute53DelegationAccess"
  role     = aws_iam_role.this.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = ["sts:AssumeRole"],
        Resource = "arn:aws:iam::${var.platform_utility_account_id}:role/Route53DelegationWrite"
      }
    ]
  })
}

# Attach the AdministratorAccess policy to the IAM role in the member_account
resource "aws_iam_role_policy_attachment" "admin_access" {
  provider  = aws.member_account
  role      = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Create IAM user for breakglass admin access
resource "aws_iam_user" "breakglass_admin" {
  provider = aws.member_account
  name     = local.breakglass_username
  path     = "/system/"
}

# Create login profile for console access
resource "aws_iam_user_login_profile" "breakglass_admin" {
  provider                    = aws.member_account
  user                        = aws_iam_user.breakglass_admin.name
  password_reset_required     = true
  password_length             = 24
  #pgp_key                     = var.pgp_key # Base64-encoded PGP public key for secure password delivery
}

# Attach administrator policy to user
resource "aws_iam_user_policy_attachment" "admin_policy" {
  provider   = aws.member_account
  user       = aws_iam_user.breakglass_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Create a TFE variable set for the IAM role in the project
# Variable set name must be unique in organization

resource "tfe_variable_set" "this" {
  name         = "${var.tfc_project_name}-${aws_iam_role.this.name}"
  description  = "OIDC federation configuration for HCP Terraform"
  organization = var.tfc_organization_name 
}

resource "tfe_variable" "tfc_aws_provider_auth" {
  key             = "TFC_AWS_PROVIDER_AUTH"
  value           = "true"
  category        = "env"
  variable_set_id = tfe_variable_set.this.id
}

resource "tfe_variable" "tfc_aws_oidc_role_arn" {
  sensitive       = true
  key             = "TFC_AWS_RUN_ROLE_ARN"
  value           = aws_iam_role.this.arn
  category        = "env"
  variable_set_id = tfe_variable_set.this.id
}

data "tfe_project" "this" {
  name = var.tfc_project_name 
  organization = var.tfc_organization_name
}

resource "tfe_project_variable_set" "this" {
  project_id    = data.tfe_project.this.id
  variable_set_id = tfe_variable_set.this.id
}
