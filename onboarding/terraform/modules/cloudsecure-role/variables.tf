# CloudSecure Role Module - Variables

variable "cloudsecure_account_id" {
  description = "The AWS Account ID where CloudSecure is deployed"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.cloudsecure_account_id))
    error_message = "Must be a valid 12-digit AWS Account ID."
  }
}

variable "external_id" {
  description = "The External ID provided by CloudSecure (prevents confused deputy attacks)"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.external_id) >= 16 && length(var.external_id) <= 128
    error_message = "External ID must be between 16 and 128 characters."
  }
}

variable "role_name" {
  description = "Name for the IAM role"
  type        = string
  default     = "CloudSecureAssessmentRole"

  validation {
    condition     = can(regex("^[a-zA-Z0-9+=,.@_-]+$", var.role_name))
    error_message = "Role name must match pattern [a-zA-Z0-9+=,.@_-]+"
  }
}

variable "permissions_boundary_arn" {
  description = "ARN of a permissions boundary policy to attach (optional)"
  type        = string
  default     = ""
}

variable "max_session_duration" {
  description = "Maximum session duration in seconds (3600-43200)"
  type        = number
  default     = 3600

  validation {
    condition     = var.max_session_duration >= 3600 && var.max_session_duration <= 43200
    error_message = "Session duration must be between 3600 (1 hour) and 43200 (12 hours)."
  }
}

variable "tags" {
  description = "Additional tags to apply to the IAM role"
  type        = map(string)
  default     = {}
}
