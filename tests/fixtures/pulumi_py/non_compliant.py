import pulumi
import pulumi_aws as aws

bucket = aws.s3.BucketV2("data-lake-bucket")

table = aws.dynamodb.Table(
    "config-table",
    attributes=[
        {"name": "id", "type": "S"},
    ],
    hash_key="id",
    billing_mode="PAY_PER_REQUEST",
)

function = aws.lambda_.Function(
    "processor-function",
    runtime="python3.11",
    handler="index.handler",
    code=pulumi.FileArchive("lambda"),
    role="arn:aws:iam::123456789012:role/lambda-role",
)
