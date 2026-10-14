output "url" {
  description = "The service's public_url."
  value       = "https://${var.domain}"
}

output "lb_dns_name" {
  description = "Point domain at it (a CNAME or an alias) when route53_zone_id is not given."
  value       = aws_lb.lb.dns_name
}

output "task_role_arn" {
  description = "The service's identity: grant it nothing more than the recipe does."
  value       = aws_iam_role.task.arn
}

output "kek" {
  value = aws_kms_key.kek.arn
}

output "mac_key" {
  value = aws_kms_key.root.arn
}

output "cluster" {
  value = aws_ecs_cluster.cluster.name
}

output "command_task_definition" {
  description = "aws ecs run-task with this, the subnets and the security group below, and the command's arguments (the README)."
  value       = aws_ecs_task_definition.command.family
}

output "private_subnet_ids" {
  value = local.private
}

output "task_security_group" {
  value = aws_security_group.task.id
}
