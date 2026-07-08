resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  point_in_time_recovery {
    enabled = true
  }
  tags = {
    "cost-center"       = "TODO-fill-in"
    "owner"             = "TODO-fill-in"
    "environment"       = "TODO-fill-in"
    "workload"          = "TODO-fill-in"
    "data-residency"    = "TODO-fill-in"
    "data-class"        = "TODO-fill-in"
    "portability-class" = "TODO-fill-in"
    "purpose"           = "TODO-fill-in"
  }
}

resource "aws_instance" "web" {
  ami                         = "ami-12345678"
  instance_type               = "t3.xlarge"
  associate_public_ip_address = false
  encrypted                   = true
  root_block_device {
    delete_on_termination = true
  }
  tags = {
    "cost-center"             = "TODO-fill-in"
    "owner"                   = "TODO-fill-in"
    "environment"             = "TODO-fill-in"
    "workload"                = "TODO-fill-in"
    "rightsizing-reviewed"    = "TODO-fill-in"
    "last-finops-review"      = "TODO-fill-in"
    "capacity-commitment"     = "TODO-fill-in"
    "sustainability-reviewed" = "TODO-fill-in"
  }
}

resource "aws_dynamodb_table" "agent_memory" {
  name         = "agent-memory"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"
  point_in_time_recovery {
    enabled = true
  }
  stream_enabled = true
  ttl {
    enabled = true
  }
  tags = {
    "data-residency"    = "TODO-fill-in"
    "data-class"        = "TODO-fill-in"
    "portability-class" = "TODO-fill-in"
  }
}

resource "aws_bedrockagent" "support" {
  agent_name = "customer-support"
  human_interaction_configuration {
    human_interpretation_prompt              = "Review agent decision"
    human_interpretation_timeout             = 3600
    human_interpretation_output_context_name = "approval"
  }
}

resource "aws_sqs_queue" "agent_messages" {
  name = "agent-messages"
}

resource "aws_lambda_function" "agent_handler" {
  function_name = "agent-handler"
  environment {
    variables = {
      AWS_XRAY_TRACING_NAME = "TODO-fill-in"
    }
  }
  memory_size = 256
  timeout     = 10
  tags = {
    "cost-center" = "TODO-fill-in"
    "owner"       = "TODO-fill-in"
    "environment" = "TODO-fill-in"
    "workload"    = "TODO-fill-in"
  }
}

resource "aws_budgets_budget" "agent_budget" {
  budget_name  = "agent-monthly-budget"
  budget_type  = "COST"
  limit_amount = "500"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  notification {
    notification_type          = "ACTUAL"
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_state         = "ALARM"
    subscriber_email_addresses = []
  }
}

provider "aws" {
  region = "eu-central-1"
}
