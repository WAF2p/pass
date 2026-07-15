resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.xlarge"
}

resource "aws_dynamodb_table" "agent_memory" {
  name         = "agent-memory"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"
}

resource "aws_bedrockagent" "support" {
  agent_name = "customer-support"
}

resource "aws_sqs_queue" "agent_messages" {
  name = "agent-messages"
}

resource "aws_lambda_function" "agent_handler" {
  function_name = "agent-handler"
}

resource "aws_budgets_budget" "agent_budget" {
  budget_name  = "agent-monthly-budget"
  budget_type  = "COST"
  limit_amount = "500"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
}

provider "aws" {
}
