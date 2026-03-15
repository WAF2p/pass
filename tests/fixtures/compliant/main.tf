resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  tags = {
    cost-center  = "platform"
    owner        = "infra-team"
    environment  = "production"
    workload     = "data-storage"
    data-residency = "eu-only"
    data-class   = "operational"
  }
}

resource "aws_budgets_budget" "monthly" {
  name         = "monthly-budget"
  budget_type  = "COST"
  limit_amount = "1000"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = ["team@example.com"]
  }
}

provider "aws" {
  region = "eu-central-1"
}
