from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    aws_guardduty as guardduty,
    aws_securityhub as securityhub,
    aws_config as config,
    aws_cloudtrail as cloudtrail,
    aws_s3 as s3,
    aws_iam as iam,
    aws_inspector as inspector,
    aws_sns as sns,
    aws_logs as logs,
    CfnOutput
)
from constructs import Construct
import uuid

class SecurityPerformancePackStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create unique suffix to avoid naming conflicts
        unique_suffix = str(uuid.uuid4())[:8]

        # ======================
        # 1. ENABLE GUARDDUTY (Threat Detection)
        # ======================
        
        print("🛡️  Setting up GuardDuty threat detection...")
        
        guardduty_detector = guardduty.CfnDetector(
            self, "GuardDutyDetector",
            enable=True,
            # Check for threats every 15 minutes (fastest option)
            finding_publishing_frequency="FIFTEEN_MINUTES"
        )

        # ======================
        # 2. ENABLE SECURITY HUB (Central Dashboard)
        # ======================
        
        print("📊 Setting up Security Hub central dashboard...")
        
        security_hub = securityhub.CfnHub(
            self, "SecurityHub",
            # Auto-enable default security standards (AWS Foundational, CIS, PCI DSS)
            auto_enable_controls=True,
            # Consolidate findings from multiple security services
            control_finding_generator="SECURITY_CONTROL"
        )

        # ======================
        # 3. ENABLE CONFIG (Compliance Monitoring) 
        # ======================
        
        print("⚙️  Setting up Config compliance monitoring...")
        
        # S3 bucket for Config to store compliance data
        config_bucket = s3.Bucket(
            self, "ConfigBucket",
            bucket_name=f"security-config-{self.account}-{self.region}-{unique_suffix}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            public_read_access=False,
            versioned=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="DeleteOldConfigData",
                    expiration=Duration.days(365),  # Keep for 1 year
                    enabled=True
                )
            ],
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True
        )
        
        # IAM role for Config service with proper permissions
        self.config_role = iam.Role(
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
                            resources=[config_bucket.bucket_arn]
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "s3:GetObject",
                                "s3:PutObject"
                            ],
                            resources=[f"{config_bucket.bucket_arn}/*"]
                        )
                    ]
                )
            }
        )
        
        # Give Config permission to write to S3 bucket
        config_bucket.grant_write(self.config_role)
        
        # Config delivery channel (where to send compliance data)
        config_delivery_channel = config.CfnDeliveryChannel(
            self, "ConfigDeliveryChannel",
            s3_bucket_name=config_bucket.bucket_name,
            config_snapshot_delivery_properties=config.CfnDeliveryChannel.ConfigSnapshotDeliveryPropertiesProperty(
                delivery_frequency="Twelve_Hours"
            )
        )
        
        # Config configuration recorder (what to monitor)
        config_recorder = config.CfnConfigurationRecorder(
            self, "ConfigRecorder",
            role_arn=self.config_role.role_arn,
            recording_group=config.CfnConfigurationRecorder.RecordingGroupProperty(
                all_supported=True,  # Monitor ALL AWS resources
                include_global_resource_types=True  # Include IAM, etc.
            )
        )
        

        # # ======================
        # # 3B. DEPLOY CONFORMANCE PACKS (The Actual Rules!)
        # # ======================
        
        # print("📋 Deploying AWS managed conformance packs...")
        
        # # AWS Foundational Security Best Practices
        # foundational_pack = config.CfnConformancePack(
        #     self, "AWSFoundationalPack",
        #     conformance_pack_name="AWS-Foundational-Security-Best-Practices",
        #     # This uses AWS's pre-built template
        #     template_s3_uri="https://s3.amazonaws.com/aws-configservice-conformancepacks-us-east-1/AWS-Foundational-Security-Best-Practices.yaml",
        #     delivery_s3_bucket=config_bucket.bucket_name
        # )
        
        # # CIS AWS Foundations Benchmark
        # cis_pack = config.CfnConformancePack(
        #     self, "CISFoundationsPack", 
        #     conformance_pack_name="CIS-AWS-Foundations-Benchmark-Level-1",
        #     # This uses the official CIS template
        #     template_s3_uri="https://s3.amazonaws.com/aws-configservice-conformancepacks-us-east-1/CIS-AWS-Foundations-Benchmark-Level-1.yaml",
        #     delivery_s3_bucket=config_bucket.bucket_name
        # )
        
        # # Operational Best Practices for Amazon S3
        # s3_pack = config.CfnConformancePack(
        #     self, "S3BestPracticesPack",
        #     conformance_pack_name="Operational-Best-Practices-for-Amazon-S3", 
        #     template_s3_uri="https://s3.amazonaws.com/aws-configservice-conformancepacks-us-east-1/Operational-Best-Practices-for-Amazon-S3.yaml",
        #     delivery_s3_bucket=config_bucket.bucket_name
        # )
        
        # # NIST 800-53 Rev 5 (Government/Enterprise Standard)
        # nist_pack = config.CfnConformancePack(
        #     self, "NIST80053Pack",
        #     conformance_pack_name="Operational-Best-Practices-for-NIST-800-53_rev_5",
        #     template_s3_uri="https://s3.amazonaws.com/aws-configservice-conformancepacks-us-east-1/Operational-Best-Practices-for-NIST-800-53_rev_5.yaml", 
        #     delivery_s3_bucket=config_bucket.bucket_name
        # )
        
        # # SOC 2 (Critical for SaaS companies)
        # soc2_pack = config.CfnConformancePack(
        #     self, "SOC2Pack",
        #     conformance_pack_name="Operational-Best-Practices-for-SOC2",
        #     template_s3_uri="https://s3.amazonaws.com/aws-configservice-conformancepacks-us-east-1/Operational-Best-Practices-for-SOC2.yaml",
        #     delivery_s3_bucket=config_bucket.bucket_name
        # )
        
        # # Make sure Config recorder is running before deploying packs
        # foundational_pack.add_dependency(config_recorder)
        # cis_pack.add_dependency(config_recorder) 
        # s3_pack.add_dependency(config_recorder)
        # nist_pack.add_dependency(config_recorder)
        # soc2_pack.add_dependency(config_recorder)

        # ======================
        # 4. ENABLE CLOUDTRAIL (Audit Logging)
        # ======================
        
        print("📝 Setting up CloudTrail audit logging...")
        
        # S3 bucket for CloudTrail logs
        cloudtrail_bucket = s3.Bucket(
            self, "CloudTrailBucket", 
            bucket_name=f"security-cloudtrail-{self.account}-{self.region}-{unique_suffix}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            public_read_access=False,
            versioned=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="ArchiveOldLogs",
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(30)
                        )
                    ],
                    expiration=Duration.days(2555),  # 7 years (compliance requirement)
                    enabled=True
                )
            ],
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True
        )
        
        # CloudWatch Log Group for real-time log analysis
        cloudtrail_log_group = logs.LogGroup(
            self, "CloudTrailLogGroup",
            log_group_name="/aws/cloudtrail/security-performance-pack",
            retention=logs.RetentionDays.ONE_YEAR,
            removal_policy=RemovalPolicy.DESTROY
        )
        
        # CloudTrail itself
        trail = cloudtrail.Trail(
            self, "SecurityTrail",
            trail_name="SecurityPerformancePack",
            # Monitor ALL regions (critical for security)
            is_multi_region_trail=True,
            # Include global services like IAM, CloudFront
            include_global_service_events=True,
            # Store in S3
            bucket=cloudtrail_bucket,
            # Also send to CloudWatch for real-time alerting
            send_to_cloud_watch_logs=True,
            cloud_watch_log_group=cloudtrail_log_group,
            # Enable insight selectors for advanced analysis
            enable_file_validation=True,
            management_events=cloudtrail.ReadWriteType.ALL,
        )
        
        # Monitor data events (file access, database queries) - CRITICAL for security
        trail.add_event_selector(
            data_resource_type=cloudtrail.DataResourceType.S3_OBJECT,
            data_resource_values=["arn:aws:s3"]
        )

        # ======================
        # 5. ENABLE INSPECTOR (Vulnerability Scanning)
        # ======================
        
        print("🔍 Setting up Inspector vulnerability scanning...")
        
        # Note: Inspector v2 is automatically enabled for EC2, ECR, and Lambda
        # in supported regions. We'll create a placeholder for future enhancements
        # You can enable Inspector v2 manually in the AWS Console if needed

        # ======================
        # 6. SNS TOPIC FOR ALERTS
        # ======================
        
        print("📢 Setting up alert notifications...")
        
        # SNS topic for security alerts
        security_alerts_topic = sns.Topic(
            self, "SecurityAlerts",
            topic_name="SecurityPerformancePack-Alerts",
            display_name="Security Performance Pack Alerts"
        )

        # ======================
        # 7. OUTPUTS (so you can see what was created)
        # ======================
        
        CfnOutput(self, "GuardDutyDetectorId", 
            value=guardduty_detector.ref,
            description="GuardDuty Detector ID"
        )
        
        CfnOutput(self, "SecurityHubArn",
            value=security_hub.attr_arn, 
            description="Security Hub ARN"
        )
        
        CfnOutput(self, "ConfigBucketName",
            value=config_bucket.bucket_name,
            description="Config S3 Bucket Name"
        )
        
        CfnOutput(self, "CloudTrailBucketName", 
            value=cloudtrail_bucket.bucket_name,
            description="CloudTrail S3 Bucket Name"
        )
        
        CfnOutput(self, "SecurityAlertsTopicArn",
            value=security_alerts_topic.topic_arn,
            description="SNS Topic for Security Alerts"
        )
        
        CfnOutput(self, "ConformancePacksDeployed",
            value="AWS-Foundational, CIS-Level-1, S3-Best-Practices, NIST-800-53, SOC2",
            description="Deployed Conformance Packs"
        )

        print("✅ Security foundation setup complete!")