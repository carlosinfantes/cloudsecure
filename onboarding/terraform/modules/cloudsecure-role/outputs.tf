# CloudSecure Role Module - Outputs

output "role_arn" {
  description = "ARN of the CloudSecure assessment role"
  value       = aws_iam_role.cloudsecure.arn
}

output "role_name" {
  description = "Name of the CloudSecure assessment role"
  value       = aws_iam_role.cloudsecure.name
}

output "role_id" {
  description = "Unique ID of the CloudSecure assessment role"
  value       = aws_iam_role.cloudsecure.unique_id
}

output "instructions" {
  description = "Next steps after deployment"
  value       = <<-EOT
    CloudSecure role created successfully!

    Role ARN: ${aws_iam_role.cloudsecure.arn}

    Next steps:
    1. Copy the Role ARN above
    2. Return to CloudSecure and paste the Role ARN
    3. Start your first security assessment

    This role provides read-only access to your AWS resources
    for security assessment purposes only.
  EOT
}
