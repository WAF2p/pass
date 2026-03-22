# WAF++ PASS — Blast Radius Analysis

> **59** failing resource(s) affect **11** downstream resource(s).

```mermaid
graph LR

    aws_instance__web["aws_instance.web\nFAIL: WAF-COST-030 · WAF-COST-060 · WAF-SUS-050 · WAF-SUS-100\nMEDIUM"]
    aws_launch_template__eks_nodes["aws_launch_template.eks_nodes\nFAIL: WAF-COST-030 · WAF-COST-090 · WAF-PERF-090 · WAF-SEC-050\nHIGH"]
    aws_cloudwatch_log_group__app_logs["aws_cloudwatch_log_group.app_logs\nFAIL: WAF-COST-040 · WAF-COST-070 · WAF-OPS-030 · WAF-SEC-100 · WAF-SOV-040 · WAF-SOV-040\nHIGH"]
    aws_cloudwatch_log_group__access_logs["aws_cloudwatch_log_group.access_logs\nFAIL: WAF-COST-040 · WAF-COST-070 · WAF-OPS-030 · WAF-SEC-100 · WAF-SOV-040 · WAF-SOV-040\nHIGH"]
    aws_kinesis_stream__raw_ingest["aws_kinesis_stream.raw_ingest\nFAIL: WAF-COST-050\nHIGH"]
    aws_eks_cluster__main["aws_eks_cluster.main\nFAIL: WAF-COST-060 · WAF-SUS-100\nMEDIUM"]
    aws_vpc_endpoint__s3_us_east["aws_vpc_endpoint.s3_us_east\nFAIL: WAF-COST-090 · WAF-PERF-070\nHIGH"]
    aws_vpc_endpoint__s3_singapore["aws_vpc_endpoint.s3_singapore\nFAIL: WAF-COST-090 · WAF-PERF-070\nHIGH"]
    aws_cloudwatch_log_group__debug_logs["aws_cloudwatch_log_group.debug_logs\nFAIL: WAF-OPS-030 · WAF-SEC-100 · WAF-SOV-040 · WAF-SOV-040\nHIGH"]
    aws_cloudwatch_log_group__vpc_flow_logs["aws_cloudwatch_log_group.vpc_flow_logs\nFAIL: WAF-OPS-030 · WAF-SEC-100 · WAF-SOV-040 · WAF-SOV-040\nHIGH"]
    aws_lambda_function__event_processor["aws_lambda_function.event_processor\nFAIL: WAF-OPS-030 · WAF-PERF-080 · WAF-SUS-070\nHIGH"]
    aws_cloudwatch_metric_alarm__high_lambda_errors["aws_cloudwatch_metric_alarm.high_lambda_errors\nFAIL: WAF-OPS-040 · WAF-OPS-060 · WAF-PERF-050 · WAF-REL-010\nCRITICAL"]
    aws_cloudwatch_metric_alarm__root_usage["aws_cloudwatch_metric_alarm.root_usage\nFAIL: WAF-OPS-060 · WAF-PERF-050\nHIGH"]
    aws_cloudwatch_metric_alarm__iam_policy_changes["aws_cloudwatch_metric_alarm.iam_policy_changes\nFAIL: WAF-OPS-060 · WAF-PERF-050\nHIGH"]
    aws_cloudtrail__main["aws_cloudtrail.main\nFAIL: WAF-OPS-090 · WAF-SEC-080 · WAF-SOV-040 · WAF-SOV-070\nHIGH"]
    aws_db_instance__main["aws_db_instance.main\nFAIL: WAF-PERF-040 · WAF-PERF-090 · WAF-SEC-030 · WAF-SEC-130 · WAF-SOV-030\nHIGH"]
    aws_kms_key__main["aws_kms_key.main\nFAIL: WAF-SEC-030\nHIGH"]
    aws_secretsmanager_secret__db_password["aws_secretsmanager_secret.db_password\nFAIL: WAF-SEC-060\nCRITICAL"]
    aws_secretsmanager_secret__api_key["aws_secretsmanager_secret.api_key\nFAIL: WAF-SEC-060\nCRITICAL"]
    aws_cloudwatch_log_group__cloudtrail["aws_cloudwatch_log_group.cloudtrail\nFAIL: WAF-SEC-100 · WAF-SOV-040 · WAF-SOV-040\nHIGH"]
    aws_cloudwatch_log_group__app_mumbai["aws_cloudwatch_log_group.app_mumbai\nFAIL: WAF-SEC-100 · WAF-SOV-040 · WAF-SOV-040\nHIGH"]
    aws_cloudwatch_log_group__app_sao_paulo["aws_cloudwatch_log_group.app_sao_paulo\nFAIL: WAF-SEC-100 · WAF-SOV-040 · WAF-SOV-040\nHIGH"]
    aws_cloudwatch_log_group__app_cape_town["aws_cloudwatch_log_group.app_cape_town\nFAIL: WAF-SEC-100 · WAF-SOV-040 · WAF-SOV-040\nHIGH"]
    aws_dynamodb_table__sessions["aws_dynamodb_table.sessions\nFAIL: WAF-SEC-130 · WAF-SOV-030 · WAF-SOV-100\nHIGH"]
    aws_dynamodb_table__analytics_events["aws_dynamodb_table.analytics_events\nFAIL: WAF-SEC-130 · WAF-SOV-030 · WAF-SOV-100\nHIGH"]
    aws_elasticache_cluster__session["aws_elasticache_cluster.session\nFAIL: WAF-SEC-130\nHIGH"]
    aws_s3_bucket__assets_us["aws_s3_bucket.assets_us\nFAIL: WAF-SEC-130 · WAF-SUS-090\nHIGH"]
    aws_s3_bucket__assets_us_west["aws_s3_bucket.assets_us_west\nFAIL: WAF-SEC-130 · WAF-SOV-100 · WAF-SUS-090\nHIGH"]
    aws_s3_bucket__assets_tokyo["aws_s3_bucket.assets_tokyo\nFAIL: WAF-SEC-130 · WAF-SOV-100 · WAF-SUS-090\nHIGH"]
    aws_s3_bucket__assets_canada["aws_s3_bucket.assets_canada\nFAIL: WAF-SEC-130 · WAF-SOV-100 · WAF-SUS-090\nHIGH"]
    aws_s3_bucket__data_lake["aws_s3_bucket.data_lake\nFAIL: WAF-SEC-130 · WAF-SUS-090\nHIGH"]
    aws_s3_bucket__logs_raw["aws_s3_bucket.logs_raw\nFAIL: WAF-SEC-130 · WAF-SOV-100 · WAF-SUS-090\nHIGH"]
    aws_s3_bucket__backups["aws_s3_bucket.backups\nFAIL: WAF-SEC-130 · WAF-SUS-090\nHIGH"]
    aws_s3_bucket__cloudtrail["aws_s3_bucket.cloudtrail\nFAIL: WAF-SEC-130 · WAF-SOV-100 · WAF-SUS-090\nHIGH"]
    aws_s3_bucket_versioning__data_lake["aws_s3_bucket_versioning.data_lake\nFAIL: WAF-SOV-030 · WAF-SOV-100\nHIGH"]
    aws_iam_account_password_policy__main["aws_iam_account_password_policy.main\nFAIL: WAF-SOV-060\nCRITICAL"]
    aws_cloudwatch_log_metric_filter__root_usage["aws_cloudwatch_log_metric_filter.root_usage\nFAIL: WAF-SOV-070\nHIGH"]
    terraform["terraform\nFAIL: WAF-SOV-080 · WAF-SOV-080 · WAF-SOV-080 · WAF-SOV-080 · WAF-SOV-080 · WAF-SOV-080 · WAF-SOV-080 · WAF-SOV-080 · WAF-SOV-080\nMEDIUM"]
    aws_security_group__internal_app["aws_security_group.internal_app\nFAIL: WAF-SOV-090\nHIGH"]
    aws_security_group__public_alb["aws_security_group.public_alb\nFAIL: WAF-SOV-090\nHIGH"]
    google_storage_bucket__assets_us["google_storage_bucket.assets_us\nFAIL: WAF-SOV-100\nMEDIUM"]
    google_storage_bucket__assets_eu["google_storage_bucket.assets_eu\nFAIL: WAF-SOV-100\nMEDIUM"]
    google_storage_bucket__assets_tokyo["google_storage_bucket.assets_tokyo\nFAIL: WAF-SOV-100\nMEDIUM"]
    google_storage_bucket__assets_singapore["google_storage_bucket.assets_singapore\nFAIL: WAF-SOV-100\nMEDIUM"]
    google_storage_bucket__assets_sydney["google_storage_bucket.assets_sydney\nFAIL: WAF-SOV-100\nMEDIUM"]
    google_storage_bucket__assets_sao_paulo["google_storage_bucket.assets_sao_paulo\nFAIL: WAF-SOV-100\nMEDIUM"]
    google_storage_bucket__assets_mumbai["google_storage_bucket.assets_mumbai\nFAIL: WAF-SOV-100\nMEDIUM"]
    google_storage_bucket__assets_montreal["google_storage_bucket.assets_montreal\nFAIL: WAF-SOV-100\nMEDIUM"]
    provider__alicloud["provider.alicloud\nFAIL: WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030\nMEDIUM"]
    provider__aws["provider.aws\nFAIL: WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030\nMEDIUM"]
    provider__azurerm["provider.azurerm\nFAIL: WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030\nMEDIUM"]
    provider__google["provider.google\nFAIL: WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030\nMEDIUM"]
    provider__oci["provider.oci\nFAIL: WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030 · WAF-SUS-030\nMEDIUM"]
    provider__yandex["provider.yandex\nFAIL: WAF-SUS-030 · WAF-SUS-030\nMEDIUM"]
    azurerm_resource_group__eastus["azurerm_resource_group.eastus\nFAIL: WAF-SUS-030\nMEDIUM"]
    azurerm_resource_group__uksouth["azurerm_resource_group.uksouth\nFAIL: WAF-SUS-030\nMEDIUM"]
    azurerm_resource_group__japaneast["azurerm_resource_group.japaneast\nFAIL: WAF-SUS-030\nMEDIUM"]
    azurerm_resource_group__brazilsouth["azurerm_resource_group.brazilsouth\nFAIL: WAF-SUS-030\nMEDIUM"]
    azurerm_resource_group__centralindia["azurerm_resource_group.centralindia\nFAIL: WAF-SUS-030\nMEDIUM"]
    aws_cloudwatch_log_metric_filter__iam_policy_changes["aws_cloudwatch_log_metric_filter.iam_policy_changes\nHIGH"]
    aws_eks_node_group__main["aws_eks_node_group.main\nHIGH"]
    aws_flow_log__main["aws_flow_log.main\nHIGH"]
    aws_kms_alias__main["aws_kms_alias.main\nHIGH"]
    aws_s3_bucket_lifecycle_configuration__backups["aws_s3_bucket_lifecycle_configuration.backups\nHIGH"]
    aws_s3_bucket_lifecycle_configuration__data_lake["aws_s3_bucket_lifecycle_configuration.data_lake\nHIGH"]
    aws_s3_bucket_lifecycle_configuration__logs_raw["aws_s3_bucket_lifecycle_configuration.logs_raw\nHIGH"]
    aws_s3_bucket_public_access_block__cloudtrail["aws_s3_bucket_public_access_block.cloudtrail\nHIGH"]
    aws_s3_bucket_server_side_encryption_configuration__backups["aws_s3_bucket_server_side_encryption_configuration.backups\nHIGH"]
    aws_s3_bucket_server_side_encryption_configuration__data_lake["aws_s3_bucket_server_side_encryption_configuration.data_lake\nHIGH"]
    aws_s3_bucket_server_side_encryption_configuration__logs_raw["aws_s3_bucket_server_side_encryption_configuration.logs_raw\nHIGH"]

    aws_launch_template__eks_nodes --> aws_eks_node_group__main
    aws_eks_cluster__main --> aws_eks_node_group__main
    aws_cloudwatch_log_group__vpc_flow_logs --> aws_flow_log__main
    aws_lambda_function__event_processor --> aws_cloudwatch_metric_alarm__high_lambda_errors
    aws_kms_key__main --> aws_dynamodb_table__sessions
    aws_kms_key__main --> aws_instance__web
    aws_kms_key__main --> aws_kms_alias__main
    aws_kms_key__main --> aws_launch_template__eks_nodes
    aws_kms_key__main --> aws_s3_bucket_server_side_encryption_configuration__data_lake
    aws_kms_key__main --> aws_secretsmanager_secret__api_key
    aws_kms_key__main --> aws_secretsmanager_secret__db_password
    aws_cloudwatch_log_group__cloudtrail --> aws_cloudtrail__main
    aws_cloudwatch_log_group__cloudtrail --> aws_cloudwatch_log_metric_filter__iam_policy_changes
    aws_cloudwatch_log_group__cloudtrail --> aws_cloudwatch_log_metric_filter__root_usage
    aws_s3_bucket__data_lake --> aws_s3_bucket_lifecycle_configuration__data_lake
    aws_s3_bucket__data_lake --> aws_s3_bucket_server_side_encryption_configuration__data_lake
    aws_s3_bucket__data_lake --> aws_s3_bucket_versioning__data_lake
    aws_s3_bucket__logs_raw --> aws_s3_bucket_lifecycle_configuration__logs_raw
    aws_s3_bucket__logs_raw --> aws_s3_bucket_server_side_encryption_configuration__logs_raw
    aws_s3_bucket__backups --> aws_s3_bucket_lifecycle_configuration__backups
    aws_s3_bucket__backups --> aws_s3_bucket_server_side_encryption_configuration__backups
    aws_s3_bucket__cloudtrail --> aws_cloudtrail__main
    aws_s3_bucket__cloudtrail --> aws_s3_bucket_public_access_block__cloudtrail
    aws_security_group__internal_app --> aws_db_instance__main
    aws_security_group__internal_app --> aws_eks_cluster__main
    aws_security_group__internal_app --> aws_instance__web

    style aws_instance__web fill:#f1c40f,stroke:#f1c40f,color:#333333
    style aws_launch_template__eks_nodes fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_cloudwatch_log_group__app_logs fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_cloudwatch_log_group__access_logs fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_kinesis_stream__raw_ingest fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_eks_cluster__main fill:#f1c40f,stroke:#f1c40f,color:#333333
    style aws_vpc_endpoint__s3_us_east fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_vpc_endpoint__s3_singapore fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_cloudwatch_log_group__debug_logs fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_cloudwatch_log_group__vpc_flow_logs fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_lambda_function__event_processor fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_cloudwatch_metric_alarm__high_lambda_errors fill:#c0392b,stroke:#c0392b,color:#ffffff
    style aws_cloudwatch_metric_alarm__root_usage fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_cloudwatch_metric_alarm__iam_policy_changes fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_cloudtrail__main fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_db_instance__main fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_kms_key__main fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_secretsmanager_secret__db_password fill:#c0392b,stroke:#c0392b,color:#ffffff
    style aws_secretsmanager_secret__api_key fill:#c0392b,stroke:#c0392b,color:#ffffff
    style aws_cloudwatch_log_group__cloudtrail fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_cloudwatch_log_group__app_mumbai fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_cloudwatch_log_group__app_sao_paulo fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_cloudwatch_log_group__app_cape_town fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_dynamodb_table__sessions fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_dynamodb_table__analytics_events fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_elasticache_cluster__session fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket__assets_us fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket__assets_us_west fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket__assets_tokyo fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket__assets_canada fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket__data_lake fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket__logs_raw fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket__backups fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket__cloudtrail fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket_versioning__data_lake fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_iam_account_password_policy__main fill:#c0392b,stroke:#c0392b,color:#ffffff
    style aws_cloudwatch_log_metric_filter__root_usage fill:#e67e22,stroke:#e67e22,color:#ffffff
    style terraform fill:#f1c40f,stroke:#f1c40f,color:#333333
    style aws_security_group__internal_app fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_security_group__public_alb fill:#e67e22,stroke:#e67e22,color:#ffffff
    style google_storage_bucket__assets_us fill:#f1c40f,stroke:#f1c40f,color:#333333
    style google_storage_bucket__assets_eu fill:#f1c40f,stroke:#f1c40f,color:#333333
    style google_storage_bucket__assets_tokyo fill:#f1c40f,stroke:#f1c40f,color:#333333
    style google_storage_bucket__assets_singapore fill:#f1c40f,stroke:#f1c40f,color:#333333
    style google_storage_bucket__assets_sydney fill:#f1c40f,stroke:#f1c40f,color:#333333
    style google_storage_bucket__assets_sao_paulo fill:#f1c40f,stroke:#f1c40f,color:#333333
    style google_storage_bucket__assets_mumbai fill:#f1c40f,stroke:#f1c40f,color:#333333
    style google_storage_bucket__assets_montreal fill:#f1c40f,stroke:#f1c40f,color:#333333
    style provider__alicloud fill:#f1c40f,stroke:#f1c40f,color:#333333
    style provider__aws fill:#f1c40f,stroke:#f1c40f,color:#333333
    style provider__azurerm fill:#f1c40f,stroke:#f1c40f,color:#333333
    style provider__google fill:#f1c40f,stroke:#f1c40f,color:#333333
    style provider__oci fill:#f1c40f,stroke:#f1c40f,color:#333333
    style provider__yandex fill:#f1c40f,stroke:#f1c40f,color:#333333
    style azurerm_resource_group__eastus fill:#f1c40f,stroke:#f1c40f,color:#333333
    style azurerm_resource_group__uksouth fill:#f1c40f,stroke:#f1c40f,color:#333333
    style azurerm_resource_group__japaneast fill:#f1c40f,stroke:#f1c40f,color:#333333
    style azurerm_resource_group__brazilsouth fill:#f1c40f,stroke:#f1c40f,color:#333333
    style azurerm_resource_group__centralindia fill:#f1c40f,stroke:#f1c40f,color:#333333
    style aws_cloudwatch_log_metric_filter__iam_policy_changes fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_eks_node_group__main fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_flow_log__main fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_kms_alias__main fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket_lifecycle_configuration__backups fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket_lifecycle_configuration__data_lake fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket_lifecycle_configuration__logs_raw fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket_public_access_block__cloudtrail fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket_server_side_encryption_configuration__backups fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket_server_side_encryption_configuration__data_lake fill:#e67e22,stroke:#e67e22,color:#ffffff
    style aws_s3_bucket_server_side_encryption_configuration__logs_raw fill:#e67e22,stroke:#e67e22,color:#ffffff
```

## Resource summary

| Resource | Criticality | Hop | Failed controls |
|---|---|---|---|
| `aws_cloudtrail.main` | 🟠 HIGH | 0 | WAF-OPS-090, WAF-SEC-080, WAF-SOV-040, WAF-SOV-070 |
| `aws_cloudwatch_log_group.access_logs` | 🟠 HIGH | 0 | WAF-COST-040, WAF-COST-070, WAF-OPS-030, WAF-SEC-100, WAF-SOV-040, WAF-SOV-040 |
| `aws_cloudwatch_log_group.app_cape_town` | 🟠 HIGH | 0 | WAF-SEC-100, WAF-SOV-040, WAF-SOV-040 |
| `aws_cloudwatch_log_group.app_logs` | 🟠 HIGH | 0 | WAF-COST-040, WAF-COST-070, WAF-OPS-030, WAF-SEC-100, WAF-SOV-040, WAF-SOV-040 |
| `aws_cloudwatch_log_group.app_mumbai` | 🟠 HIGH | 0 | WAF-SEC-100, WAF-SOV-040, WAF-SOV-040 |
| `aws_cloudwatch_log_group.app_sao_paulo` | 🟠 HIGH | 0 | WAF-SEC-100, WAF-SOV-040, WAF-SOV-040 |
| `aws_cloudwatch_log_group.cloudtrail` | 🟠 HIGH | 0 | WAF-SEC-100, WAF-SOV-040, WAF-SOV-040 |
| `aws_cloudwatch_log_group.debug_logs` | 🟠 HIGH | 0 | WAF-OPS-030, WAF-SEC-100, WAF-SOV-040, WAF-SOV-040 |
| `aws_cloudwatch_log_group.vpc_flow_logs` | 🟠 HIGH | 0 | WAF-OPS-030, WAF-SEC-100, WAF-SOV-040, WAF-SOV-040 |
| `aws_cloudwatch_log_metric_filter.root_usage` | 🟠 HIGH | 0 | WAF-SOV-070 |
| `aws_cloudwatch_metric_alarm.high_lambda_errors` | 🔴 CRITICAL | 0 | WAF-OPS-040, WAF-OPS-060, WAF-PERF-050, WAF-REL-010 |
| `aws_cloudwatch_metric_alarm.iam_policy_changes` | 🟠 HIGH | 0 | WAF-OPS-060, WAF-PERF-050 |
| `aws_cloudwatch_metric_alarm.root_usage` | 🟠 HIGH | 0 | WAF-OPS-060, WAF-PERF-050 |
| `aws_db_instance.main` | 🟠 HIGH | 0 | WAF-PERF-040, WAF-PERF-090, WAF-SEC-030, WAF-SEC-130, WAF-SOV-030 |
| `aws_dynamodb_table.analytics_events` | 🟠 HIGH | 0 | WAF-SEC-130, WAF-SOV-030, WAF-SOV-100 |
| `aws_dynamodb_table.sessions` | 🟠 HIGH | 0 | WAF-SEC-130, WAF-SOV-030, WAF-SOV-100 |
| `aws_eks_cluster.main` | 🟡 MEDIUM | 0 | WAF-COST-060, WAF-SUS-100 |
| `aws_elasticache_cluster.session` | 🟠 HIGH | 0 | WAF-SEC-130 |
| `aws_iam_account_password_policy.main` | 🔴 CRITICAL | 0 | WAF-SOV-060 |
| `aws_instance.web` | 🟡 MEDIUM | 0 | WAF-COST-030, WAF-COST-060, WAF-SUS-050, WAF-SUS-100 |
| `aws_kinesis_stream.raw_ingest` | 🟠 HIGH | 0 | WAF-COST-050 |
| `aws_kms_key.main` | 🟠 HIGH | 0 | WAF-SEC-030 |
| `aws_lambda_function.event_processor` | 🟠 HIGH | 0 | WAF-OPS-030, WAF-PERF-080, WAF-SUS-070 |
| `aws_launch_template.eks_nodes` | 🟠 HIGH | 0 | WAF-COST-030, WAF-COST-090, WAF-PERF-090, WAF-SEC-050 |
| `aws_s3_bucket.assets_canada` | 🟠 HIGH | 0 | WAF-SEC-130, WAF-SOV-100, WAF-SUS-090 |
| `aws_s3_bucket.assets_tokyo` | 🟠 HIGH | 0 | WAF-SEC-130, WAF-SOV-100, WAF-SUS-090 |
| `aws_s3_bucket.assets_us` | 🟠 HIGH | 0 | WAF-SEC-130, WAF-SUS-090 |
| `aws_s3_bucket.assets_us_west` | 🟠 HIGH | 0 | WAF-SEC-130, WAF-SOV-100, WAF-SUS-090 |
| `aws_s3_bucket.backups` | 🟠 HIGH | 0 | WAF-SEC-130, WAF-SUS-090 |
| `aws_s3_bucket.cloudtrail` | 🟠 HIGH | 0 | WAF-SEC-130, WAF-SOV-100, WAF-SUS-090 |
| `aws_s3_bucket.data_lake` | 🟠 HIGH | 0 | WAF-SEC-130, WAF-SUS-090 |
| `aws_s3_bucket.logs_raw` | 🟠 HIGH | 0 | WAF-SEC-130, WAF-SOV-100, WAF-SUS-090 |
| `aws_s3_bucket_versioning.data_lake` | 🟠 HIGH | 0 | WAF-SOV-030, WAF-SOV-100 |
| `aws_secretsmanager_secret.api_key` | 🔴 CRITICAL | 0 | WAF-SEC-060 |
| `aws_secretsmanager_secret.db_password` | 🔴 CRITICAL | 0 | WAF-SEC-060 |
| `aws_security_group.internal_app` | 🟠 HIGH | 0 | WAF-SOV-090 |
| `aws_security_group.public_alb` | 🟠 HIGH | 0 | WAF-SOV-090 |
| `aws_vpc_endpoint.s3_singapore` | 🟠 HIGH | 0 | WAF-COST-090, WAF-PERF-070 |
| `aws_vpc_endpoint.s3_us_east` | 🟠 HIGH | 0 | WAF-COST-090, WAF-PERF-070 |
| `azurerm_resource_group.brazilsouth` | 🟡 MEDIUM | 0 | WAF-SUS-030 |
| `azurerm_resource_group.centralindia` | 🟡 MEDIUM | 0 | WAF-SUS-030 |
| `azurerm_resource_group.eastus` | 🟡 MEDIUM | 0 | WAF-SUS-030 |
| `azurerm_resource_group.japaneast` | 🟡 MEDIUM | 0 | WAF-SUS-030 |
| `azurerm_resource_group.uksouth` | 🟡 MEDIUM | 0 | WAF-SUS-030 |
| `google_storage_bucket.assets_eu` | 🟡 MEDIUM | 0 | WAF-SOV-100 |
| `google_storage_bucket.assets_montreal` | 🟡 MEDIUM | 0 | WAF-SOV-100 |
| `google_storage_bucket.assets_mumbai` | 🟡 MEDIUM | 0 | WAF-SOV-100 |
| `google_storage_bucket.assets_sao_paulo` | 🟡 MEDIUM | 0 | WAF-SOV-100 |
| `google_storage_bucket.assets_singapore` | 🟡 MEDIUM | 0 | WAF-SOV-100 |
| `google_storage_bucket.assets_sydney` | 🟡 MEDIUM | 0 | WAF-SOV-100 |
| `google_storage_bucket.assets_tokyo` | 🟡 MEDIUM | 0 | WAF-SOV-100 |
| `google_storage_bucket.assets_us` | 🟡 MEDIUM | 0 | WAF-SOV-100 |
| `provider.alicloud` | 🟡 MEDIUM | 0 | WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030 |
| `provider.aws` | 🟡 MEDIUM | 0 | WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030 |
| `provider.azurerm` | 🟡 MEDIUM | 0 | WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030 |
| `provider.google` | 🟡 MEDIUM | 0 | WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030 |
| `provider.oci` | 🟡 MEDIUM | 0 | WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030, WAF-SUS-030 |
| `provider.yandex` | 🟡 MEDIUM | 0 | WAF-SUS-030, WAF-SUS-030 |
| `terraform` | 🟡 MEDIUM | 0 | WAF-SOV-080, WAF-SOV-080, WAF-SOV-080, WAF-SOV-080, WAF-SOV-080, WAF-SOV-080, WAF-SOV-080, WAF-SOV-080, WAF-SOV-080 |
| `aws_cloudwatch_log_metric_filter.iam_policy_changes` | 🟠 HIGH | 1 | — |
| `aws_eks_node_group.main` | 🟠 HIGH | 1 | — |
| `aws_flow_log.main` | 🟠 HIGH | 1 | — |
| `aws_kms_alias.main` | 🟠 HIGH | 1 | — |
| `aws_s3_bucket_lifecycle_configuration.backups` | 🟠 HIGH | 1 | — |
| `aws_s3_bucket_lifecycle_configuration.data_lake` | 🟠 HIGH | 1 | — |
| `aws_s3_bucket_lifecycle_configuration.logs_raw` | 🟠 HIGH | 1 | — |
| `aws_s3_bucket_public_access_block.cloudtrail` | 🟠 HIGH | 1 | — |
| `aws_s3_bucket_server_side_encryption_configuration.backups` | 🟠 HIGH | 1 | — |
| `aws_s3_bucket_server_side_encryption_configuration.data_lake` | 🟠 HIGH | 1 | — |
| `aws_s3_bucket_server_side_encryption_configuration.logs_raw` | 🟠 HIGH | 1 | — |

---

| Icon | Criticality | Meaning |
|---|---|---|
| 🔴 | CRITICAL | Root cause — control failure at critical severity |
| 🟠 | HIGH | Directly depends on a failing resource (1 hop) or high-severity failure |
| 🟡 | MEDIUM | Two hops from a failing resource |
| ⚪ | LOW | Three or more hops from a failing resource |