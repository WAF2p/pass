import pulumi
import pulumi_aws as aws

bucket = aws.s3.BucketV2(
    "data-lake-bucket",
    versioning={"enabled": True},
)

table = aws.dynamodb.Table(
    "config-table",
    attributes=[
        {"name": "id", "type": "S"},
    ],
    hash_key="id",
    billing_mode="PAY_PER_REQUEST",
    point_in_time_recovery={"enabled": True},
)

function = aws.lambda_.Function(
    "processor-function",
    runtime="python3.11",
    handler="index.handler",
    code=pulumi.FileArchive("lambda"),
    role="arn:aws:iam::123456789012:role/lambda-role",
    environment={"variables": {"AWS_XRAY_TRACING_NAME": "processor-function"}},
)
