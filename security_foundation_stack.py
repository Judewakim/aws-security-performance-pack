from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    CfnParameter,
    CfnCondition,
    CfnResource,
    Fn,
    aws_guardduty as guardduty,
    aws_securityhub as securityhub,
    aws_config as config,
    aws_cloudtrail as cloudtrail,
    aws_s3_assets as s3_assets,
    aws_s3 as s3,
    aws_iam as iam,
    aws_sns as sns,
    aws_events as events,
    aws_events_targets as targets,
    aws_lambda as lambda_,
    CfnOutput
)
from constructs import Construct
from typing import cast
import os
import requests

class SecurityFoundationStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ======================
        # CLOUDFORMATION PARAMETERS
        # ======================
        
        # Email addresses for alerts (comma-separated)
        alert_emails = CfnParameter(
            self, "AlertEmails",
            type="String",
            description="Email address(es) for security alerts (comma-separated)",
            constraint_description="Must be valid email address(es)"
        )
        
        # Conformance pack selections
        enable_aws_foundational = CfnParameter(
            self, "EnableAWSFoundational",
            type="String",
            default="true",
            allowed_values=["true", "false"],
            description="Enable AWS Foundational Security Best Practices conformance pack"
        )
        
        enable_cis_foundations = CfnParameter(
            self, "EnableCISFoundations", 
            type="String",
            default="true",
            allowed_values=["true", "false"],
            description="Enable CIS AWS Foundations Benchmark conformance pack"
        )
        
        # Alert severity threshold
        alert_severity = CfnParameter(
            self, "AlertSeverity",
            type="String",
            default="CRITICAL",
            allowed_values=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            description="Minimum severity level for SNS alerts"
        )
        
        # Security Hub subscription parameter
        subscribe_security_hub = CfnParameter(
            self, "SubscribeSecurityHub",
            type="String",
            default="true",
            allowed_values=["true", "false"],
            description="Create Security Hub resource (set to false if already subscribed)"
        )

        # ======================
        # CONDITIONS
        # ======================
        
        # Condition to enable Config (if any conformance pack is selected)
        enable_config_condition = CfnCondition(
            self, "EnableConfigCondition",
            expression=Fn.condition_or(
                Fn.condition_equals(enable_aws_foundational.value_as_string, "true"),
                Fn.condition_equals(enable_cis_foundations.value_as_string, "true")
            )
        )
        
        aws_foundational_condition = CfnCondition(
            self, "AWSFoundationalCondition",
            expression=Fn.condition_equals(enable_aws_foundational.value_as_string, "true")
        )
        
        cis_foundations_condition = CfnCondition(
            self, "CISFoundationsCondition", 
            expression=Fn.condition_equals(enable_cis_foundations.value_as_string, "true")
        )
        
        security_hub_condition = CfnCondition(
            self, "SecurityHubCondition",
            expression=Fn.condition_equals(subscribe_security_hub.value_as_string, "true")
        )

        # ======================
        # 1. SNS ALERTING SETUP (First, so other services can reference it)
        # ======================
        
        # Security alerts topic
        security_alerts_topic = sns.Topic(
            self, "SecurityAlerts",
            display_name="AWS Security Foundation Alerts",
            topic_name=f"SecurityFoundation-Alerts-{self.account}"
        )
        
        # Email subscriptions (split comma-separated emails)
        email_subscription = sns.CfnSubscription(
            self, "AlertEmailSubscription",
            topic_arn=security_alerts_topic.topic_arn,
            protocol="email",
            endpoint=alert_emails.value_as_string
        )

        # ======================
        # 2. S3 BUCKETS WITH LIFECYCLE POLICIES
        # ======================
        
        # Centralized security events bucket (SIEM-ready)
        security_events_bucket = s3.Bucket(
            self, "SecurityEventsBucket",
            bucket_name=f"security-events-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            public_read_access=False,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="SecurityEventsLifecycle",
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=Duration.days(30)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(90)
                        )
                    ],
                    expiration=Duration.days(2555),  # 7 years
                    enabled=True
                )
            ],
            removal_policy=RemovalPolicy.DESTROY
        )
        
        # Config bucket (conditional)
        config_bucket = s3.Bucket(
            self, "ConfigBucket",
            bucket_name=f"security-config-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            public_read_access=False,
            versioned=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="ConfigDataLifecycle",
                    expiration=Duration.days(365),  # 1 year
                    enabled=True
                )
            ],
            removal_policy=RemovalPolicy.DESTROY
        )
        cast(s3.CfnBucket, config_bucket.node.default_child).cfn_options.condition = enable_config_condition
        
        # CloudTrail bucket
        cloudtrail_bucket = s3.Bucket(
            self, "CloudTrailBucket",
            bucket_name=f"security-cloudtrail-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            public_read_access=False,
            versioned=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="CloudTrailLifecycle",
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(30)
                        )
                    ],
                    expiration=Duration.days(2555),  # 7 years
                    enabled=True
                )
            ],
            removal_policy=RemovalPolicy.DESTROY
        )

        # ======================
        # 3. GUARDDUTY (Threat Detection)
        # ======================
        
        guardduty_detector = guardduty.CfnDetector(
            self, "GuardDutyDetector",
            enable=True,
            finding_publishing_frequency="FIFTEEN_MINUTES"
        )

        # ======================
        # 4. SECURITY HUB (Central Dashboard)
        # ======================
        
        # Enable AWS Foundational Security Best Practices standard (conditional)
        foundational_standard = securityhub.CfnStandard(
            self, "FoundationalStandard",
            standards_arn=f"arn:aws:securityhub:{self.region}:{self.account}:standards/aws-foundational-security-best-practices/v/1.0.0"
        )
        foundational_standard.cfn_options.condition = security_hub_condition

        # ======================
        # 5. INSPECTOR V2 (Vulnerability Scanning)
        # ======================
        
        # # Enable Inspector v2
        # inspector_v2 = CfnResource(
        #     self, "InspectorV2",
        #     type="AWS::Inspector2::Enabler",
        #     properties={
        #         "AccountIds": [self.account],
        #         "ResourceTypes": ["EC2", "ECR", "LAMBDA"]
        #     }
        # )

        # ======================
        # 6. CLOUDTRAIL (Audit Logging)
        # ======================
        
        trail = cloudtrail.CfnTrail(
            self, "SecurityTrail",
            trail_name="SecurityFoundation",
            is_multi_region_trail=True,
            is_logging=True,
            include_global_service_events=True,
            s3_bucket_name=cloudtrail_bucket.bucket_name,
            enable_log_file_validation=True,
            event_selectors=[
                cloudtrail.CfnTrail.EventSelectorProperty(
                    read_write_type="All",
                    include_management_events=True
                )
            ]
        )

        # ======================
        # 7. CONFIG (Conditional - Only if conformance packs selected)
        # ======================
        
        # Config IAM role
        config_role = iam.Role(
            self, "ConfigRole",
            assumed_by=iam.ServicePrincipal("config.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWS_ConfigRole")
            ],
            inline_policies={
                "ConfigS3Policy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "s3:GetBucketAcl",
                                "s3:GetBucketLocation",
                                "s3:ListBucket"
                            ],
                            resources=[f"arn:aws:s3:::security-config-{self.account}-{self.region}"]
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "s3:GetObject",
                                "s3:PutObject"
                            ],
                            resources=[f"arn:aws:s3:::security-config-{self.account}-{self.region}/*"]
                        )
                    ]
                )
            }
        )
        cast(iam.CfnRole, config_role.node.default_child).cfn_options.condition = enable_config_condition
        
        # Config delivery channel
        config_delivery_channel = config.CfnDeliveryChannel(
            self, "ConfigDeliveryChannel",
            s3_bucket_name=config_bucket.bucket_name,
            config_snapshot_delivery_properties=config.CfnDeliveryChannel.ConfigSnapshotDeliveryPropertiesProperty(
                delivery_frequency="Twelve_Hours"
            )
        )
        config_delivery_channel.cfn_options.condition = enable_config_condition
        
        # Config recorder
        config_recorder = config.CfnConfigurationRecorder(
            self, "ConfigRecorder",
            role_arn=config_role.role_arn,
            recording_group=config.CfnConfigurationRecorder.RecordingGroupProperty(
                all_supported=True,
                include_global_resource_types=True
            )
        )
        config_recorder.cfn_options.condition = enable_config_condition

        # ======================
        # 8. CONFORMANCE PACKS (Conditional)
        # ======================

        # Helper function to download AWS-managed conformance pack YAML
        def stage_aws_managed_pack(pack_name: str, url: str) -> s3_assets.Asset:
            # Create local directory for CDK asset
            local_dir = f"cdk_assets/conformance_packs/{pack_name}"
            os.makedirs(local_dir, exist_ok=True)
            local_file = os.path.join(local_dir, f"{pack_name}.yaml")

            # Download the YAML
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            with open(local_file, "w") as f:
                f.write(response.text)

            # Create an S3 asset
            asset = s3_assets.Asset(self, f"{pack_name}Asset", path=local_file)
            return asset

        # AWS-managed URLs
        AWS_FOUNDATIONAL_URL = "https://raw.githubusercontent.com/awslabs/aws-config-rules/master/aws-config-conformance-packs/Operational-Best-Practices-for-AWS-Foundational-Security-Best-Practices.yaml"
        CIS_FOUNDATIONS_URL = "https://raw.githubusercontent.com/awslabs/aws-config-rules/master/aws-config-conformance-packs/Operational-Best-Practices-for-CIS-AWS-v1.4-Level1.yaml"

        # Stage assets
        aws_foundational_asset = stage_aws_managed_pack("AWSFoundationalPack", AWS_FOUNDATIONAL_URL)
        cis_foundations_asset = stage_aws_managed_pack("CISFoundationsPack", CIS_FOUNDATIONS_URL)

        # Create Conformance Packs pointing to the staged asset in S3
        aws_foundational_pack = config.CfnConformancePack(
            self, "AWSFoundationalPack",
            conformance_pack_name="AWS-Foundational-Security-Best-Practices",
            template_s3_uri=aws_foundational_asset.s3_object_url,
            delivery_s3_bucket=config_bucket.bucket_name
        )
        aws_foundational_pack.cfn_options.condition = aws_foundational_condition
        aws_foundational_pack.add_dependency(config_recorder)

        cis_foundations_pack = config.CfnConformancePack(
            self, "CISFoundationsPack",
            conformance_pack_name="CIS-AWS-Foundations-Benchmark",
            template_s3_uri=cis_foundations_asset.s3_object_url,
            delivery_s3_bucket=config_bucket.bucket_name
        )
        cis_foundations_pack.cfn_options.condition = cis_foundations_condition
        cis_foundations_pack.add_dependency(config_recorder)



        # ======================
        # 9. EVENT ROUTING TO CENTRALIZED BUCKET
        # ======================
        
        # Lambda function to process and route security events
        event_processor_role = iam.Role(
            self, "EventProcessorRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ],
            inline_policies={
                "S3WritePolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["s3:PutObject"],
                            resources=[f"{security_events_bucket.bucket_arn}/*"]
                        )
                    ]
                )
            }
        )
        
        event_processor = lambda_.Function(
            self, "SecurityEventProcessor",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            role=event_processor_role,
            timeout=Duration.minutes(5),
            environment={
                "EVENTS_BUCKET": security_events_bucket.bucket_name
            },
            code=lambda_.Code.from_inline("""
import json
import boto3
import uuid
from datetime import datetime
import os

s3 = boto3.client('s3')
events_bucket = os.environ['EVENTS_BUCKET']

def handler(event, context):
    try:
        # Determine event source and create structured path
        source = event.get('source', 'unknown')
        detail_type = event.get('detail-type', 'unknown')
        
        # Create timestamp-based path structure
        now = datetime.utcnow()
        date_str = now.strftime('%Y-%m-%d')
        
        # Generate unique filename
        event_id = str(uuid.uuid4())[:8]
        
        # Create structured S3 key
        if source == 'aws.guardduty':
            s3_key = f"guardduty/{now.year}/{now.month:02d}/{date_str}-finding-{event_id}.json"
        elif source == 'aws.securityhub':
            s3_key = f"securityhub/{now.year}/{now.month:02d}/{date_str}-finding-{event_id}.json"
        elif source == 'aws.config':
            s3_key = f"config/{now.year}/{now.month:02d}/{date_str}-compliance-{event_id}.json"
        else:
            s3_key = f"other/{now.year}/{now.month:02d}/{date_str}-event-{event_id}.json"
        
        # Add metadata
        enriched_event = {
            'ingestion_timestamp': now.isoformat(),
            'event_id': event_id,
            'source_service': source,
            'detail_type': detail_type,
            'original_event': event
        }
        
        # Store in S3
        s3.put_object(
            Bucket=events_bucket,
            Key=s3_key,
            Body=json.dumps(enriched_event, indent=2),
            ContentType='application/json',
            ServerSideEncryption='AES256'
        )
        
        return {'statusCode': 200, 'body': f'Event stored: {s3_key}'}
        
    except Exception as e:
        print(f"Error processing event: {str(e)}")
        raise e
            """)
        )
        
        # EventBridge rules for routing security events (no additional cost)
        # GuardDuty findings
        guardduty_rule = events.Rule(
            self, "GuardDutyRule",
            event_pattern=events.EventPattern(
                source=["aws.guardduty"],
                detail_type=["GuardDuty Finding"]
            ),
            targets=[targets.LambdaFunction(event_processor)]
        )
        
        # Security Hub findings
        securityhub_rule = events.Rule(
            self, "SecurityHubRule", 
            event_pattern=events.EventPattern(
                source=["aws.securityhub"],
                detail_type=["Security Hub Findings - Imported"]
            ),
            targets=[targets.LambdaFunction(event_processor)]
        )
        
        # Config compliance changes
        config_rule = events.Rule(
            self, "ConfigRule",
            event_pattern=events.EventPattern(
                source=["aws.config"],
                detail_type=["Config Rules Compliance Change"]
            ),
            targets=[targets.LambdaFunction(event_processor)]
        )
        cast(events.CfnRule, config_rule.node.default_child).cfn_options.condition = enable_config_condition

        # ======================
        # 10. SECURITY HUB ALERTING
        # ======================
        
        # Lambda for Security Hub alerts
        alert_processor_role = iam.Role(
            self, "AlertProcessorRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ],
            inline_policies={
                "SNSPublishPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["sns:Publish"],
                            resources=[security_alerts_topic.topic_arn]
                        )
                    ]
                )
            }
        )
        
        alert_processor = lambda_.Function(
            self, "SecurityAlertProcessor",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            role=alert_processor_role,
            timeout=Duration.minutes(2),
            environment={
                "SNS_TOPIC_ARN": security_alerts_topic.topic_arn,
                "ALERT_SEVERITY": alert_severity.value_as_string
            },
            code=lambda_.Code.from_inline("""
import json
import boto3
import os

sns = boto3.client('sns')
topic_arn = os.environ['SNS_TOPIC_ARN']
alert_severity = os.environ['ALERT_SEVERITY']

# Severity hierarchy
SEVERITY_LEVELS = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}

def handler(event, context):
    try:
        # Extract Security Hub finding details
        detail = event.get('detail', {})
        findings = detail.get('findings', [])
        
        for finding in findings:
            severity_label = finding.get('Severity', {}).get('Label', 'UNKNOWN')
            
            # Check if severity meets threshold
            if SEVERITY_LEVELS.get(severity_label, 0) >= SEVERITY_LEVELS.get(alert_severity, 4):
                
                # Create alert message
                title = finding.get('Title', 'Security Finding')
                description = finding.get('Description', 'No description available')
                resource_id = finding.get('Resources', [{}])[0].get('Id', 'Unknown resource')
                
                message = f\"\"\"SECURITY ALERT - {severity_label} SEVERITY

Title: {title}
Resource: {resource_id}
Description: {description}

Time: {finding.get('CreatedAt', 'Unknown')}

Please review this finding in the AWS Security Hub console.
                \"\"\".strip()
                
                # Send SNS alert
                sns.publish(
                    TopicArn=topic_arn,
                    Subject=f\"ALERT: {severity_label} Security Alert - {title}\",
                    Message=message
                )
        
        return {'statusCode': 200}
        
    except Exception as e:
        print(f\"Error processing alert: {str(e)}\")
        raise e
            """)
        )
        
        # EventBridge rule for Security Hub alerts
        securityhub_alert_rule = events.Rule(
            self, "SecurityHubAlertRule",
            event_pattern=events.EventPattern(
                source=["aws.securityhub"],
                detail_type=["Security Hub Findings - Imported"]
            ),
            targets=[targets.LambdaFunction(alert_processor)]
        )

        # ======================
        # 11. OUTPUTS
        # ======================
        
        CfnOutput(self, "SecurityEventsBucketName",
            value=security_events_bucket.bucket_name,
            description="S3 bucket containing centralized security events (SIEM-ready)"
        )
        
        CfnOutput(self, "SecurityAlertsTopicArn", 
            value=security_alerts_topic.topic_arn,
            description="SNS topic for security alerts"
        )
        
        CfnOutput(self, "GuardDutyDetectorId",
            value=guardduty_detector.ref,
            description="GuardDuty detector ID"
        )
        
        CfnOutput(self, "CloudTrailBucketName",
            value=cloudtrail_bucket.bucket_name,
            description="CloudTrail audit logs bucket"
        )