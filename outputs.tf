# Copyright (c) GEDI, Inc.
# SPDX-License-Identifier: MPL-2.0

# OIDC Provider Details
output "oidc_provider_url" {
  description = "The URL of the HCP Terraform OIDC provider."
  value       = aws_iam_openid_connect_provider.hcp_terraform.url
}

output "oidc_provider_arn" {
  description = "The ARN of the HCP Terraform OIDC provider."
  value       = aws_iam_openid_connect_provider.hcp_terraform.arn
}

output "oidc_thumbprint" {
  description = "The SHA1 fingerprint of the TLS certificate for the OIDC provider."
  value       = data.tls_certificate.provider.certificates[0].sha1_fingerprint
}

# IAM Role Details
output "hcp_terraform_role_arn" {
  description = "The ARN of the IAM role assumed by HCP Terraform via OIDC."
  value       = aws_iam_role.this.arn
}

output "hcp_terraform_role_name" {
  description = "The name of the IAM role assumed by HCP Terraform via OIDC."
  value       = aws_iam_role.this.name
}

# Breakglass Admin Details
output "breakglass_admin_username" {
  description = "The username of the breakglass admin IAM user."
  value       = aws_iam_user.breakglass_admin.name
}

output "breakglass_admin_initial_password" {
  description = "The initial password for the breakglass admin IAM user (encrypted if PGP key is provided)."
  value       = aws_iam_user_login_profile.breakglass_admin.password
  sensitive   = true
}

# HCP Terraform Variable Set Details
output "tfe_variable_set_id" {
  description = "The ID of the HCP Terraform variable set containing OIDC configuration."
  value       = tfe_variable_set.this.id
}

output "tfe_variable_set_name" {
  description = "The name of the HCP Terraform variable set containing OIDC configuration."
  value       = tfe_variable_set.this.name
}

output "tfe_project_id" {
  description = "The ID of the HCP Terraform project associated with the variable set."
  value       = data.tfe_project.this.id
}