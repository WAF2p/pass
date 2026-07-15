import * as cdk from 'aws-cdk-lib';
import * as aws_s3 from 'aws-cdk-lib/aws-s3';
import * as aws_dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as aws_lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';

export class CompliantStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    new aws_s3.Bucket(this, 'DataLakeBucket', {
      versioned: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    new aws_dynamodb.Table(this, 'ConfigTable', {
      partitionKey: { name: 'id', type: aws_dynamodb.AttributeType.STRING },
      billingMode: aws_dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true,
    });

    new aws_lambda.Function(this, 'ProcessorFunction', {
      runtime: aws_lambda.Runtime.PYTHON_3_11,
      handler: 'index.handler',
      code: aws_lambda.Code.fromAsset('lambda'),
      environment: {
        AWS_XRAY_TRACING_NAME: 'processor-function',
      },
    });
  }
}
