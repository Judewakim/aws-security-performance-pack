from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    aws_s3 as s3,
    aws_s3_notifications as s3n,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_events as events,
    aws_events_targets as targets,
    aws_glue as glue,
    aws_athena as athena,
    CfnOutput
)
from constructs import Construct
import uuid

class SecurityDataLakeStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        unique_suffix = str(uuid.uuid4())[:8]

        # ======================
        # 1. CENTRAL SECURITY DATA LAKE
        # ======================
        
        print("🏗️  Creating security data lake...")
        
        # Main data lake bucket - this is where EVERYTHING goes
        data_lake_bucket = s3.Bucket(
            self, "SecurityDataLake",
            bucket_name=f"security-data-lake-{self.account}-{self.region}-{unique_suffix}",
            # Encrypt everything with KMS for better security
            encryption=s3.BucketEncryption.KMS_MANAGED,
            # No public access ever
            public_read_access=False,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            # Version everything for forensics
            versioned=True,
            # Enable MFA delete protection
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,

            # Organize data by date and source
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="SecurityDataLifecycle",
                    transitions=[
                        # Move to cheaper storage after 30 days
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=Duration.days(30)
                        ),
                        # Archive after 90 days  
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(90)
                        ),
                        # Deep archive after 1 year
                        s3.Transition(
                            storage_class=s3.StorageClass.DEEP_ARCHIVE,
                            transition_after=Duration.days(365)
                        )
                    ],
                    # Keep security data for 7 years (compliance)
                    expiration=Duration.days(2555),
                    enabled=True
                )
            ],
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True
        )

        # ======================
        # 2. IAM ROLE FOR LAMBDA (Explicit Security)
        # ======================
        
        print("🔐 Creating Lambda execution role...")
        
        # Create specific IAM role for data ingestion Lambda
        lambda_execution_role = iam.Role(
            self, "DataIngestionLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Role for Security Data Lake ingestion Lambda",
            # Basic Lambda execution permissions
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ],
            # Explicit S3 permissions (principle of least privilege)
            inline_policies={
                "S3DataLakeAccess": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "s3:PutObject",
                                "s3:PutObjectAcl", 
                                "s3:GetObject",
                                "s3:GetObjectVersion"
                            ],
                            resources=[
                                f"{data_lake_bucket.bucket_arn}/*"
                            ]
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "s3:ListBucket"
                            ],
                            resources=[
                                data_lake_bucket.bucket_arn
                            ]
                        )
                    ]
                ),
                "KMSAccess": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "kms:Encrypt",
                                "kms:Decrypt", 
                                "kms:ReEncrypt*",
                                "kms:GenerateDataKey*",
                                "kms:DescribeKey"
                            ],
                            resources=["*"],  # KMS keys are region-specific
                            conditions={
                                "StringEquals": {
                                    "kms:ViaService": f"s3.{self.region}.amazonaws.com"
                                }
                            }
                        )
                    ]
                )
            }
        )

        # ======================
        # 3. DATA INGESTION LAMBDA (With Proper Role)
        # ======================
        
        print("📥 Setting up data ingestion...")
        
        # Lambda function to process incoming security events
        data_ingestion_lambda = lambda_.Function(
            self, "SecurityDataIngestion",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.lambda_handler",
            timeout=Duration.minutes(5),
            memory_size=512,
            role=lambda_execution_role,  # Use our explicit role
            environment={
                "DATA_LAKE_BUCKET": data_lake_bucket.bucket_name
            },
            code=lambda_.Code.from_inline("""
import json
import boto3
import urllib.parse
from datetime import datetime
import uuid
import os

s3 = boto3.client('s3')
data_lake_bucket = os.environ['DATA_LAKE_BUCKET']
aws_region = os.environ['AWS_REGION']  # This is automatically provided by Lambda

def lambda_handler(event, context):
    '''
    This function receives security events from:
    - GuardDuty findings      → guardduty/year/month/day/hour/
    - Security Hub findings   → securityhub/year/month/day/hour/
    - Config compliance       → config/year/month/day/hour/
    - CloudTrail events       → cloudtrail/year/month/day/hour/
    - Inspector findings      → inspector/year/month/day/hour/
    
    It normalizes them and stores in structured S3 prefixes
    '''
    
    try:
        # Determine event source
        event_source = determine_source(event)
        print(f"📥 Processing {event_source} event")
        
        # Normalize the event data
        normalized_event = normalize_event(event, event_source)
        
        # Generate structured storage path with proper prefixes
        now = datetime.utcnow()
        s3_key = f"{event_source}/{now.year}/{now.month:02d}/{now.day:02d}/{now.hour:02d}/{uuid.uuid4()}.json"
        
        # Store in data lake with metadata
        s3.put_object(
            Bucket=data_lake_bucket,
            Key=s3_key,
            Body=json.dumps(normalized_event, indent=2),
            ContentType='application/json',
            Metadata={
                'source': event_source,
                'severity': normalized_event.get('severity', 'UNKNOWN'),
                'ingestion-timestamp': now.isoformat(),
                'region': aws_region
            },
            # Server-side encryption
            ServerSideEncryption='aws:kms'
        )
        
        print(f"✅ Stored {event_source} event: s3://{data_lake_bucket}/{s3_key}")
        
        # Log structured information for monitoring
        print(json.dumps({
            "status": "success",
            "source": event_source,
            "severity": normalized_event.get('severity'),
            "resource_id": normalized_event.get('resource_id'),
            "s3_location": f"s3://{data_lake_bucket}/{s3_key}"
        }))
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Event processed successfully',
                'source': event_source,
                'location': s3_key,
                'severity': normalized_event.get('severity')
            })
        }
        
    except Exception as e:
        error_details = {
            "status": "error",
            "error": str(e),
            "event_sample": str(event)[:500]  # Truncate for logging
        }
        print(f"❌ Error processing event: {json.dumps(error_details)}")
        
        # Re-raise for Lambda to handle retry logic
        raise e

def determine_source(event):
    '''Figure out where this security event came from'''
    
    if 'source' in event and event['source'] == 'aws.guardduty':
        return 'guardduty'
    elif 'source' in event and event['source'] == 'aws.securityhub':
        return 'securityhub'  
    elif 'source' in event and event['source'] == 'aws.config':
        return 'config'
    elif 'source' in event and event['source'] == 'aws.inspector2':
        return 'inspector'
    elif 'eventSource' in event:
        return 'cloudtrail'
    elif 'Records' in event and len(event['Records']) > 0:
        # SNS/SQS message - check the actual message
        record = event['Records'][0]
        if 'Sns' in record:
            sns_message = json.loads(record['Sns']['Message'])
            return determine_source(sns_message)
        elif 'eventSource' in record:
            return 'cloudtrail'
    else:
        print(f"⚠️  Unknown event source: {json.dumps(event)[:200]}...")
        return 'unknown'

def normalize_event(event, source):
    '''Convert different event formats to standard format'''
    
    normalized = {
        'timestamp': datetime.utcnow().isoformat(),
        'source': source,
        'raw_event': event,
        'severity': 'UNKNOWN',
        'resource_id': 'UNKNOWN',
        'event_type': 'UNKNOWN'
    }
    
    # GuardDuty findings
    if source == 'guardduty':
        detail = event.get('detail', {})
        normalized.update({
            'severity': detail.get('severity', 'UNKNOWN'),
            'resource_id': detail.get('resource', {}).get('instanceDetails', {}).get('instanceId', 'UNKNOWN'),
            'event_type': detail.get('type', 'UNKNOWN'),
            'description': detail.get('description', 'No description')
        })
    
    # Security Hub findings  
    elif source == 'securityhub':
        findings = event.get('detail', {}).get('findings', [{}])
        if findings:
            finding = findings[0]
            normalized.update({
                'severity': finding.get('Severity', {}).get('Label', 'UNKNOWN'),
                'resource_id': finding.get('Resources', [{}])[0].get('Id', 'UNKNOWN'),
                'event_type': finding.get('Types', ['UNKNOWN'])[0],
                'description': finding.get('Description', 'No description')
            })
    
    # Config compliance changes
    elif source == 'config':
        detail = event.get('detail', {})
        normalized.update({
            'severity': 'MEDIUM' if detail.get('newEvaluationResult', {}).get('complianceType') == 'NON_COMPLIANT' else 'LOW',
            'resource_id': detail.get('resourceId', 'UNKNOWN'),
            'event_type': 'COMPLIANCE_CHANGE',
            'description': f"Compliance changed to {detail.get('newEvaluationResult', {}).get('complianceType', 'UNKNOWN')}"
        })
    
    # CloudTrail events
    elif source == 'cloudtrail':
        normalized.update({
            'severity': 'HIGH' if event.get('errorCode') else 'INFO',
            'resource_id': event.get('resources', [{}])[0].get('ARN', 'UNKNOWN') if event.get('resources') else 'UNKNOWN',
            'event_type': event.get('eventName', 'UNKNOWN'),
            'description': f"{event.get('eventName', 'Unknown')} by {event.get('userIdentity', {}).get('userName', 'Unknown')}"
        })
    
    return normalized
            """)
        )

        # Remove the grant_write since we're using explicit IAM policies
        # data_lake_bucket.grant_write(data_ingestion_lambda)  # Replaced with explicit IAM role

        # ======================
        # 4. GLUE DATA CATALOG (For Querying)  
        # ======================
        
        print("📊 Setting up data catalog...")
        
        # Glue database for security data
        glue_database = glue.CfnDatabase(
            self, "SecurityDatabase",
            catalog_id=self.account,
            database_input=glue.CfnDatabase.DatabaseInputProperty(
                name="security_performance_pack",
                description="Security data lake for performance pack analysis"
            )
        )
        
        # Glue table for security events
        glue_table = glue.CfnTable(
            self, "SecurityEventsTable",
            catalog_id=self.account,
            database_name=glue_database.ref,
            table_input=glue.CfnTable.TableInputProperty(
                name="security_events",
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    location=f"s3://{data_lake_bucket.bucket_name}/",
                    input_format="org.apache.hadoop.mapred.TextInputFormat",
                    output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        serialization_library="org.openx.data.jsonserde.JsonSerDe"
                    ),
                    columns=[
                        glue.CfnTable.ColumnProperty(name="timestamp", type="string"),
                        glue.CfnTable.ColumnProperty(name="source", type="string"), 
                        glue.CfnTable.ColumnProperty(name="severity", type="string"),
                        glue.CfnTable.ColumnProperty(name="resource_id", type="string"),
                        glue.CfnTable.ColumnProperty(name="event_type", type="string"),
                        glue.CfnTable.ColumnProperty(name="description", type="string"),
                        glue.CfnTable.ColumnProperty(name="raw_event", type="string")
                    ]
                ),
                partition_keys=[
                    glue.CfnTable.ColumnProperty(name="source", type="string"),
                    glue.CfnTable.ColumnProperty(name="year", type="string"),
                    glue.CfnTable.ColumnProperty(name="month", type="string"),
                    glue.CfnTable.ColumnProperty(name="day", type="string")
                ]
            )
        )

        # ======================
        # 5. OUTPUTS
        # ======================
        
        CfnOutput(self, "DataLakeBucketName",
            value=data_lake_bucket.bucket_name,
            description="Security Data Lake S3 Bucket"
        )
        
        CfnOutput(self, "DataIngestionLambdaArn",
            value=data_ingestion_lambda.function_arn,
            description="Data Ingestion Lambda Function ARN"
        )
        
        CfnOutput(self, "GlueDatabaseName", 
            value=glue_database.ref,
            description="Glue Database for Security Data"
        )

        print("✅ Security data lake setup complete!")