# Copyright (c) GEDI, Inc.
# SPDX-License-Identifier: MPL-2.0

# Copyright (c) GEDI, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "region" {
  description = "The AWS region where resources will be created."
  type        = string
  default     = "us-east-1"
}

variable "tfc_organization_name" {
  description = "HCP Terraform organization name."
  type        = string
}

variable "tfc_project_name" {
  description = "HCP Terraform project name within the organization."
  type        = string
}

variable "token" {
  description = "HCP Terraform admin user token for API authentication."
  type        = string
  sensitive   = true
}

variable "member_account_id" {
  description = "The AWS member account ID where the OIDC provider and role will be created."
  type        = string
}

variable "pgp_key" {
  description = "Base64-encoded PGP public key for encrypting the breakglass admin password. If not provided, the password will be output unencrypted."
  type        = string
  default     = null
}