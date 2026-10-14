# tresor-server on ECS Fargate (spec 021): its task role the only identity, the KEK in two KMS keys, references in
# Secrets Manager, PostgreSQL on RDS by IAM authentication in private subnets with no public access, an HTTPS load
# balancer, and a task definition the commands run with (spec 019). The README says what to change for production.

data "aws_caller_identity" "this" {}
data "aws_partition" "this" {}
data "aws_availability_zones" "up" {
  state = "available"
}

locals {
  name     = var.prefix
  account  = data.aws_caller_identity.this.account_id
  arn      = data.aws_partition.this.partition
  own_vpc  = var.vpc_id == ""
  vpc_id   = local.own_vpc ? aws_vpc.vpc[0].id : var.vpc_id
  private  = local.own_vpc ? aws_subnet.private[*].id : var.private_subnet_ids
  public   = local.own_vpc ? aws_subnet.public[*].id : var.public_subnet_ids
  azs      = slice(data.aws_availability_zones.up.names, 0, 2)
  cert     = var.certificate_arn != "" ? var.certificate_arn : aws_acm_certificate_validation.cert[0].certificate_arn
  db_user  = "${replace(local.name, "-", "_")}_svc"
  db_admin = "${replace(local.name, "-", "_")}_admin"
  # the service's settings: the service's and the commands' task, one identity and one configuration
  env = {
    TRESOR_LISTEN               = "0.0.0.0:8080"
    TRESOR_PUBLIC_URL           = "https://${var.domain}"
    TRESOR_TLS__OFFLOAD         = "true"
    TRESOR_AWS__REGION          = var.region
    TRESOR_STATE__KIND          = "postgres"
    TRESOR_STATE__DSN           = "host=${aws_db_instance.db.address} port=${aws_db_instance.db.port} user=${local.db_user} dbname=tresor sslmode=verify-full sslrootcert=/ca/rds.pem"
    TRESOR_STATE__AUTH          = "aws"
    TRESOR_KEYS__KIND           = "awskms"
    TRESOR_KEYS__KEY            = aws_kms_key.kek.arn
    TRESOR_KEYS__MAC_KEY        = aws_kms_key.root.arn
    TRESOR_ISSUERS              = var.issuers
    TRESOR_POLICY__ADMINS       = var.admins
    TRESOR_POLICY__ACTORS       = var.actors
    TRESOR_MATERIAL__AWS__ALLOW = yamlencode([{ prefixes = var.material_prefixes }])
  }
}

# --- the network: private subnets for the tasks and the database, a NAT for the internet (the IdP, the image) ---

resource "aws_vpc" "vpc" {
  count                = local.own_vpc ? 1 : 0
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${local.name}-vpc" }
}

resource "aws_subnet" "public" {
  count             = local.own_vpc ? 2 : 0
  vpc_id            = aws_vpc.vpc[0].id
  availability_zone = local.azs[count.index]
  cidr_block        = "10.20.${count.index}.0/24"
  tags              = { Name = "${local.name}-public-${count.index}" }
}

resource "aws_subnet" "private" {
  count             = local.own_vpc ? 2 : 0
  vpc_id            = aws_vpc.vpc[0].id
  availability_zone = local.azs[count.index]
  cidr_block        = "10.20.${count.index + 10}.0/24"
  tags              = { Name = "${local.name}-private-${count.index}" }
}

resource "aws_internet_gateway" "igw" {
  count  = local.own_vpc ? 1 : 0
  vpc_id = aws_vpc.vpc[0].id
}

resource "aws_eip" "nat" {
  count  = local.own_vpc ? 1 : 0
  domain = "vpc"
}

# one NAT gateway (one AZ): a trial's; production may want one per AZ
resource "aws_nat_gateway" "nat" {
  count         = local.own_vpc ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id
  depends_on    = [aws_internet_gateway.igw]
}

resource "aws_route_table" "public" {
  count  = local.own_vpc ? 1 : 0
  vpc_id = aws_vpc.vpc[0].id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw[0].id
  }
}

resource "aws_route_table" "private" {
  count  = local.own_vpc ? 1 : 0
  vpc_id = aws_vpc.vpc[0].id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat[0].id
  }
}

resource "aws_route_table_association" "public" {
  count          = local.own_vpc ? 2 : 0
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table_association" "private" {
  count          = local.own_vpc ? 2 : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}

data "aws_vpc" "this" {
  id = local.vpc_id
}

# VPC endpoints (optional): the tasks' traffic to AWS stays in the VPC
resource "aws_security_group" "endpoints" {
  count  = var.vpc_endpoints ? 1 : 0
  name   = "${local.name}-endpoints"
  vpc_id = local.vpc_id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.this.cidr_block]
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = var.vpc_endpoints ? toset(["kms", "secretsmanager", "sts", "logs", "ecr.api", "ecr.dkr"]) : toset([])
  vpc_id              = local.vpc_id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.private
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "s3" {
  count             = var.vpc_endpoints && local.own_vpc ? 1 : 0
  vpc_id            = local.vpc_id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private[0].id]
}

# --- security groups: the load balancer from the internet, the tasks from it, the database from the tasks -----

resource "aws_security_group" "lb" {
  name   = "${local.name}-lb"
  vpc_id = local.vpc_id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # redirected to HTTPS
  }
  egress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.this.cidr_block]
  }
}

resource "aws_security_group" "task" {
  name   = "${local.name}-task"
  vpc_id = local.vpc_id
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.lb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # the IdP, AWS's APIs, the image, the database
  }
}

resource "aws_security_group" "db" {
  name   = "${local.name}-db"
  vpc_id = local.vpc_id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.task.id]
  }
}

# --- the KEK: a key that wraps the data keys (rotated by KMS, its id kept: no rewrap), and a MAC key: the root ---

resource "aws_kms_key" "kek" {
  description             = "${local.name}: tresor-server's KEK"
  key_usage               = "ENCRYPT_DECRYPT"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_key" "root" {
  description              = "${local.name}: tresor-server's KEK root (HMAC; not rotated)"
  key_usage                = "GENERATE_VERIFY_MAC"
  customer_master_key_spec = "HMAC_256"
  deletion_window_in_days  = 30
}

resource "aws_kms_alias" "kek" {
  name          = "alias/${local.name}-kek"
  target_key_id = aws_kms_key.kek.key_id
}

resource "aws_kms_alias" "root" {
  name          = "alias/${local.name}-root"
  target_key_id = aws_kms_key.root.key_id
}

# --- the database: PostgreSQL on RDS, IAM authentication, TLS only, no public access --------------------------

resource "aws_db_subnet_group" "db" {
  name       = "${local.name}-db"
  subnet_ids = local.private
}

resource "aws_db_parameter_group" "db" {
  name   = "${local.name}-pg16"
  family = "postgres16"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_db_instance" "db" {
  identifier                          = "${local.name}-pg"
  engine                              = "postgres"
  engine_version                      = "16"
  instance_class                      = var.db_instance_class
  allocated_storage                   = 20
  storage_encrypted                   = true
  db_name                             = "tresor"
  username                            = local.db_admin
  manage_master_user_password         = true # RDS keeps and rotates it in Secrets Manager: never in Terraform's state
  iam_database_authentication_enabled = true
  db_subnet_group_name                = aws_db_subnet_group.db.name
  parameter_group_name                = aws_db_parameter_group.db.name
  vpc_security_group_ids              = [aws_security_group.db.id]
  publicly_accessible                 = false
  backup_retention_period             = 7
  deletion_protection                 = var.deletion_protection
  skip_final_snapshot                 = !var.deletion_protection
  final_snapshot_identifier           = var.deletion_protection ? "${local.name}-pg-final" : null
  apply_immediately                   = true
}

# the RDS CA, which no system trust store holds: public data, given to an init container that writes the file
data "http" "rds_ca" {
  url = "https://truststore.pki.rds.amazonaws.com/${var.region}/${var.region}-bundle.pem"
}

# --- the roles: the task's (the service's identity) and the execution role (pulls, logs, the db-init secret) ---

data "aws_iam_policy_document" "tasks" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "task" {
  name               = "${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.tasks.json
}

data "aws_iam_policy_document" "task" {
  statement {
    sid       = "TheKEK"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.kek.arn]
  }
  statement {
    sid       = "TheRoot" # the service's alone: who can wrap and MAC can plant a data key
    actions   = ["kms:GenerateMac", "kms:DescribeKey"]
    resources = [aws_kms_key.root.arn]
  }
  statement {
    sid       = "References"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [for p in var.material_prefixes : "arn:${local.arn}:secretsmanager:${var.region}:${local.account}:secret:${p}*"]
  }
  statement {
    sid       = "TheDatabase"
    actions   = ["rds-db:connect"]
    resources = ["arn:${local.arn}:rds-db:${var.region}:${local.account}:dbuser:${aws_db_instance.db.resource_id}/${local.db_user}"]
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "tresor-server"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}

resource "aws_iam_role" "execution" {
  name               = "${local.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.tasks.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:${local.arn}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# db-init's: the master password, read by ECS into that one task's environment
resource "aws_iam_role_policy" "execution" {
  name = "db-init"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_db_instance.db.master_user_secret[0].secret_arn]
    }]
  })
}

resource "aws_cloudwatch_log_group" "logs" {
  name              = "/ecs/${local.name}"
  retention_in_days = 30
}

# --- ECS -----------------------------------------------------------------------------------------------------

resource "aws_ecs_cluster" "cluster" {
  name = local.name
}

locals {
  # the init container: the RDS CA to a file the others read
  ca_container = {
    name        = "ca"
    image       = "public.ecr.aws/docker/library/busybox:stable"
    essential   = false
    command     = ["sh", "-c", "printf '%s' \"$RDS_CA\" > /ca/rds.pem"]
    environment = [{ name = "RDS_CA", value = data.http.rds_ca.response_body }]
    mountPoints = [{ sourceVolume = "ca", containerPath = "/ca" }]
    logConfiguration = {
      logDriver = "awslogs"
      options   = { "awslogs-group" = aws_cloudwatch_log_group.logs.name, "awslogs-region" = var.region, "awslogs-stream-prefix" = "ca" }
    }
  }
  tresor_container = {
    name         = "tresor"
    image        = var.image
    essential    = true
    portMappings = [{ containerPort = 8080, protocol = "tcp" }]
    environment  = [for k, v in local.env : { name = k, value = v }]
    mountPoints  = [{ sourceVolume = "ca", containerPath = "/ca", readOnly = true }]
    dependsOn    = [{ containerName = "ca", condition = "SUCCESS" }]
    logConfiguration = {
      logDriver = "awslogs"
      options   = { "awslogs-group" = aws_cloudwatch_log_group.logs.name, "awslogs-region" = var.region, "awslogs-stream-prefix" = "tresor" }
    }
  }
}

resource "aws_ecs_task_definition" "service" {
  family                   = local.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  task_role_arn            = aws_iam_role.task.arn
  execution_role_arn       = aws_iam_role.execution.arn
  volume {
    name = "ca"
  }
  container_definitions = jsonencode([local.ca_container, local.tresor_container])
}

# the commands (spec 019): this definition, the command given at run-task (the README)
resource "aws_ecs_task_definition" "command" {
  family                   = "${local.name}-command"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  task_role_arn            = aws_iam_role.task.arn
  execution_role_arn       = aws_iam_role.execution.arn
  volume {
    name = "ca"
  }
  container_definitions = jsonencode([local.ca_container, merge(local.tresor_container, { portMappings = [], command = ["refs"] })])
}

# --- the database's user and its ownership: once, as the master user, whose password RDS keeps ----------------

resource "aws_ecs_task_definition" "db_init" {
  family                   = "${local.name}-db-init"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  volume {
    name = "ca"
  }
  container_definitions = jsonencode([local.ca_container, {
    name      = "psql"
    image     = "public.ecr.aws/docker/library/postgres:16-alpine"
    essential = true
    command = ["psql",
      "host=${aws_db_instance.db.address} port=${aws_db_instance.db.port} user=${local.db_admin} dbname=tresor sslmode=verify-full sslrootcert=/ca/rds.pem",
      "-v", "ON_ERROR_STOP=1", "-c",
    "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${local.db_user}') THEN CREATE ROLE ${local.db_user} LOGIN; END IF; END $$; GRANT rds_iam TO ${local.db_user}; GRANT ${local.db_user} TO ${local.db_admin}; ALTER DATABASE tresor OWNER TO ${local.db_user};"]
    secrets     = [{ name = "PGPASSWORD", valueFrom = "${aws_db_instance.db.master_user_secret[0].secret_arn}:password::" }]
    mountPoints = [{ sourceVolume = "ca", containerPath = "/ca", readOnly = true }]
    dependsOn   = [{ containerName = "ca", condition = "SUCCESS" }]
    logConfiguration = {
      logDriver = "awslogs"
      options   = { "awslogs-group" = aws_cloudwatch_log_group.logs.name, "awslogs-region" = var.region, "awslogs-stream-prefix" = "db-init" }
    }
  }])
}

# runs it once (again when the database is replaced), waited for, retried while IAM settles: the AWS CLI where
# Terraform runs
resource "terraform_data" "db_init" {
  triggers_replace = [aws_db_instance.db.resource_id]
  provisioner "local-exec" {
    command = <<-EOT
      for i in 1 2 3 4 5; do
        task=$(aws ecs run-task --region ${var.region} --cluster ${aws_ecs_cluster.cluster.name} --launch-type FARGATE \
          --task-definition ${aws_ecs_task_definition.db_init.arn} \
          --network-configuration "awsvpcConfiguration={subnets=[${join(",", local.private)}],securityGroups=[${aws_security_group.task.id}],assignPublicIp=DISABLED}" \
          --query 'tasks[0].taskArn' --output text) || { sleep 20; continue; }
        aws ecs wait tasks-stopped --region ${var.region} --cluster ${aws_ecs_cluster.cluster.name} --tasks "$task"
        code=$(aws ecs describe-tasks --region ${var.region} --cluster ${aws_ecs_cluster.cluster.name} --tasks "$task" \
          --query "tasks[0].containers[?name=='psql'].exitCode | [0]" --output text)
        [ "$code" = 0 ] && exit 0
        sleep 20
      done
      exit 1
    EOT
  }
  depends_on = [aws_iam_role_policy.execution, aws_iam_role_policy_attachment.execution]
}

# --- HTTPS: a certificate, the load balancer, the name ---------------------------------------------------------

resource "aws_acm_certificate" "cert" {
  count             = var.certificate_arn == "" ? 1 : 0
  domain_name       = var.domain
  validation_method = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = var.certificate_arn == "" ? { for o in aws_acm_certificate.cert[0].domain_validation_options : o.domain_name => o } : {}
  zone_id  = var.route53_zone_id
  name     = each.value.resource_record_name
  type     = each.value.resource_record_type
  records  = [each.value.resource_record_value]
  ttl      = 300
}

resource "aws_acm_certificate_validation" "cert" {
  count                   = var.certificate_arn == "" ? 1 : 0
  certificate_arn         = aws_acm_certificate.cert[0].arn
  validation_record_fqdns = [for r in aws_route53_record.validation : r.fqdn]
}

resource "aws_lb" "lb" {
  name                       = local.name
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = local.public
  security_groups            = [aws_security_group.lb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = var.deletion_protection
}

resource "aws_lb_target_group" "tresor" {
  name        = local.name
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = local.vpc_id
  health_check {
    path    = "/readyz"
    matcher = "200"
  }
  deregistration_delay = 15
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.lb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = local.cert
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tresor.arn
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.lb.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_route53_record" "name" {
  count   = var.route53_zone_id != "" ? 1 : 0
  zone_id = var.route53_zone_id
  name    = var.domain
  type    = "A"
  alias {
    name                   = aws_lb.lb.dns_name
    zone_id                = aws_lb.lb.zone_id
    evaluate_target_health = false
  }
}

# --- the service ---------------------------------------------------------------------------------------------

resource "aws_ecs_service" "svc" {
  name            = local.name
  cluster         = aws_ecs_cluster.cluster.id
  task_definition = aws_ecs_task_definition.service.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = local.private
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = false
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.tresor.arn
    container_name   = "tresor"
    container_port   = 8080
  }
  health_check_grace_period_seconds = 60
  depends_on                        = [aws_lb_listener.https, terraform_data.db_init, aws_iam_role_policy.task]
}
