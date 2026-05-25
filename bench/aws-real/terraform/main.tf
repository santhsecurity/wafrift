# wafrift bench/aws-real — Terraform main.
#
# NOT APPLIED YET. This is a complete stub for when AWS creds land.
# Designed to teardown cleanly (no orphaned ENIs / EIPs / log groups).
#
# Cost when running: ~$35–45/month. Tear down after each bench.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "AWS region for the bench"
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix on every resource — keeps the bench distinguishable from prod"
  type        = string
  default     = "wafrift-bench"
}

# ── Network ────────────────────────────────────────────────────────
# Use the default VPC so we don't create / destroy network plumbing
# every bench run — cheaper and faster.
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# ── Security groups ────────────────────────────────────────────────
resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb"
  description = "Public 80/443 → ALB"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "task" {
  name        = "${var.name_prefix}-task"
  description = "ALB → Fargate task on 3000"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ── ALB ────────────────────────────────────────────────────────────
resource "aws_lb" "this" {
  name               = var.name_prefix
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = data.aws_subnets.default.ids
}

resource "aws_lb_target_group" "juice" {
  name        = "${var.name_prefix}-juice"
  port        = 3000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default.id

  health_check {
    path                = "/rest/admin/application-version"
    matcher             = "200-299"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.juice.arn
  }
}

# ── ECS Fargate Juice Shop ─────────────────────────────────────────
resource "aws_ecs_cluster" "this" {
  name = var.name_prefix
}

resource "aws_iam_role" "task_exec" {
  name = "${var.name_prefix}-task-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "task_exec" {
  role       = aws_iam_role.task_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_ecs_task_definition" "juice" {
  family                   = "${var.name_prefix}-juice"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.task_exec.arn

  container_definitions = jsonencode([{
    name      = "juice-shop"
    image     = "bkimminich/juice-shop:v17.1.1"
    essential = true
    portMappings = [{ containerPort = 3000, protocol = "tcp" }]
    environment = [{ name = "NODE_ENV", value = "unsafe" }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.juice.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "juice"
      }
    }
  }])
}

resource "aws_cloudwatch_log_group" "juice" {
  name              = "/ecs/${var.name_prefix}-juice"
  retention_in_days = 1
}

resource "aws_ecs_service" "juice" {
  name            = "${var.name_prefix}-juice"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.juice.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.juice.arn
    container_name   = "juice-shop"
    container_port   = 3000
  }

  depends_on = [aws_lb_listener.http]
}

# ── WAFv2 WebACL — the actual test subject ─────────────────────────
resource "aws_wafv2_web_acl" "this" {
  name        = var.name_prefix
  description = "wafrift bench: managed rule groups against ALB"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-acl"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "common"
    priority = 1
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "sqli"
    priority = 2
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "sqli"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "known-bad-inputs"
    priority = 3
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.this.arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

# ── Outputs ────────────────────────────────────────────────────────
output "alb_dns_name" {
  value       = aws_lb.this.dns_name
  description = "Aim wafrift at this hostname (HTTP only — no TLS cert yet)."
}

output "web_acl_id" {
  value       = aws_wafv2_web_acl.this.id
  description = "WAFv2 WebACL id for sample-request inspection in console."
}

output "cloudwatch_log_group" {
  value       = aws_cloudwatch_log_group.juice.name
  description = "Juice Shop container logs (1-day retention)."
}
