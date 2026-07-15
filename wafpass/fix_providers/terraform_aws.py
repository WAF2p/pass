"""Terraform AWS defaults for the WAF++ auto-fixer."""
from __future__ import annotations

from wafpass.fix_providers import FixProvider, fix_provider_registry

_TERRAFORM_AWS_BLOCK_DEFAULTS: dict[tuple[str, str], dict[str, object]] = {
    ("aws_s3_bucket", "versioning"): {"enabled": True},
    ("aws_s3_bucket", "server_side_encryption_configuration"): {
        "rule": {
            "apply_server_side_encryption_by_default": {
                "sse_algorithm": "AES256"
            }
        }
    },
    ("aws_s3_bucket", "logging"): {"target_bucket": "", "target_prefix": ""},
    ("aws_s3_bucket", "lifecycle_rule"): {
        "id": "default",
        "enabled": True,
        "expiration": {"days": 365},
    },
    ("aws_s3_bucket", "public_access_block"): {
        "block_public_acls": True,
        "block_public_policy": True,
        "ignore_public_acls": True,
        "restrict_public_buckets": True,
    },
    ("aws_dynamodb_table", "point_in_time_recovery"): {"enabled": True},
    ("aws_dynamodb_table", "ttl"): {"attribute_name": "expires_at", "enabled": True},
    ("aws_dynamodb_table", "server_side_encryption"): {"enabled": True},
    ("aws_dynamodb_table", "replica"): {"region_name": "us-east-1"},
    ("aws_lambda_function", "environment"): {"variables": {"AWS_XRAY_TRACING_NAME": "TODO-fill-in"}},
    ("aws_lambda_function", "tracing_config"): {"mode": "Active"},
    ("aws_lambda_function", "vpc_config"): {"subnet_ids": [], "security_group_ids": []},
    ("aws_lambda_function", "dead_letter_config"): {"target_arn": ""},
    ("aws_sqs_queue", "redrive_policy"): {"deadLetterTargetArn": "", "maxReceiveCount": 3},
    ("aws_sqs_queue", "sqs_managed_sse_enabled"): True,
    ("aws_sns_topic", "kms_master_key_id"): "alias/aws/sns",
    ("aws_bedrockagent", "guardrail_configuration"): {"guardrail_arn": "", "guardrail_version": "DRAFT"},
    ("aws_bedrockagent", "human_interaction_configuration"): {
        "human_interpretation_prompt": "Review agent decision",
        "human_interpretation_timeout": 3600,
        "human_interpretation_output_context_name": "approval",
    },
    ("aws_budgets_budget", "notification"): {
        "notification_type": "ACTUAL",
        "comparison_operator": "GREATER_THAN",
        "threshold": 80,
        "threshold_type": "PERCENTAGE",
        "notification_state": "ALARM",
        "subscriber_email_addresses": [],
    },
    ("aws_cloudwatch_log_group", "kms_key_id"): "",
    ("aws_cloudwatch_metric_alarm", "alarm_actions"): [],
    ("aws_cloudwatch_metric_alarm", "ok_actions"): [],
    ("aws_cloudwatch_metric_alarm", "insufficient_data_actions"): [],
    ("aws_rds_instance", "backup_retention_period"): 7,
    ("aws_rds_instance", "storage_encrypted"): True,
    ("aws_rds_instance", "enabled_cloudwatch_logs_exports"): [],
    ("aws_rds_cluster", "backup_retention_period"): 7,
    ("aws_rds_cluster", "storage_encrypted"): True,
    ("aws_rds_cluster", "enabled_cloudwatch_logs_exports"): [],
    ("aws_kms_key", "enable_key_rotation"): True,
    ("aws_kms_alias", "target_key_id"): "",
    ("aws_ecs_service", "deployment_circuit_breaker"): {"enable": True, "rollback": True},
    ("aws_ecs_task_definition", "container_definitions"): [],
    ("aws_ecs_cluster", "setting"): {"name": "containerInsights", "value": "enabled"},
    ("aws_eks_cluster", "encryption_config"): {"resources": ["secrets"]},
    ("aws_eks_cluster", "vpc_config"): {"subnet_ids": [], "security_group_ids": []},
    ("aws_eks_node_group", "scaling_config"): {"desired_size": 1, "max_size": 2, "min_size": 1},
    ("aws_elasticache_cluster", "snapshot_retention_limit"): 7,
    ("aws_elasticache_replication_group", "snapshot_retention_limit"): 7,
    ("aws_apigatewayv2_stage", "access_log_settings"): {"destination_arn": "", "format": ""},
    ("aws_apigateway_stage", "access_log_settings"): {"destination_arn": "", "format": ""},
    ("aws_cloudfront_distribution", "logging_config"): {"bucket": "", "prefix": ""},
    ("aws_cloudfront_distribution", "default_cache_behavior"): {
        "viewer_protocol_policy": "redirect-to-https",
    },
    ("aws_lb", "access_logs"): {"bucket": "", "enabled": True},
    ("aws_instance", "root_block_device"): {"delete_on_termination": True, "encrypted": True},
    ("aws_instance", "ebs_block_device"): {"encrypted": True},
    ("aws_instance", "metadata_options"): {"http_tokens": "required"},
    ("aws_autoscaling_group", "tag"): [],
    ("aws_iam_password_policy", "minimum_password_length"): 14,
    ("aws_iam_password_policy", "require_uppercase_characters"): True,
    ("aws_iam_password_policy", "require_lowercase_characters"): True,
    ("aws_iam_password_policy", "require_numbers"): True,
    ("aws_iam_password_policy", "require_symbols"): True,
    ("aws_iam_account_password_policy", "minimum_password_length"): 14,
    ("aws_iam_account_password_policy", "require_uppercase_characters"): True,
    ("aws_iam_account_password_policy", "require_lowercase_characters"): True,
    ("aws_iam_account_password_policy", "require_numbers"): True,
    ("aws_iam_account_password_policy", "require_symbols"): True,
    # Provider-level defaults for provider "aws" {} blocks.
    ("aws", "region"): "eu-central-1",
    ("aws", "default_tags"): {
        "tags": {
            "owner": "TODO-fill-in",
            "environment": "TODO-fill-in",
        }
    },
    # Generic tag-only controls can apply to any AWS resource.
    ("*", "tags"): {},
}


fix_provider_registry.register(
    FixProvider(
        name="terraform_aws",
        frameworks=["terraform"],
        providers=["aws"],
        block_defaults=_TERRAFORM_AWS_BLOCK_DEFAULTS,
        resource_type_prefixes=["aws_"],
        provider_block_types=["aws"],
        block_modes={("aws_sqs_queue", "redrive_policy"): "jsonencode"},
    )
)
