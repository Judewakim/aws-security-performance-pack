from aws_cdk import (
    Stack,
    RemovalPolicy,
    aws_config as config,
    aws_s3 as s3,
    CfnOutput
)
from constructs import Construct
import json
import os

class ConformancePacksStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, config_role_arn: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Load the S3 URIs from our download script
        try:
            with open('conformance-pack-uris.json', 'r') as f:
                pack_data = json.load(f)
                templates = pack_data['templates']
                bucket_name = pack_data['bucket_name']
        except FileNotFoundError:
            print("❌ conformance-pack-uris.json not found. Run download_conformance_packs.py first!")
            raise

        print(f"📋 Creating conformance packs from bucket: {bucket_name}")

        # Reference the existing S3 bucket (created by our script)
        conformance_bucket = s3.Bucket.from_bucket_name(
            self, "ConformancePacksBucket", bucket_name
        )

        # AWS Foundational Security Best Practices
        if 'aws-foundational-security-best-practices' in templates:
            aws_foundational_pack = config.CfnConformancePack(
                self, "AWSFoundationalPack",
                conformance_pack_name="aws-foundational-security-best-practices",
                template_s3_uri=templates['aws-foundational-security-best-practices'],
                delivery_s3_bucket=conformance_bucket.bucket_name
            )

        # CIS AWS Foundations Benchmark  
        if 'cis-aws-foundations-benchmark' in templates:
            cis_pack = config.CfnConformancePack(
                self, "CISFoundationsPack", 
                conformance_pack_name="cis-aws-foundations-benchmark",
                template_s3_uri=templates['cis-aws-foundations-benchmark'],
                delivery_s3_bucket=conformance_bucket.bucket_name
            )

        # NIST 800-53
        if 'nist-800-53' in templates:
            nist_pack = config.CfnConformancePack(
                self, "NIST80053Pack",
                conformance_pack_name="nist-800-53-rev4", 
                template_s3_uri=templates['nist-800-53'],
                delivery_s3_bucket=conformance_bucket.bucket_name
            )

        # PCI DSS (this covers SOC 2 type requirements)
        if 'pci-dss' in templates:
            pci_pack = config.CfnConformancePack(
                self, "PCIDSSPack",
                conformance_pack_name="pci-dss-3-2-1",
                template_s3_uri=templates['pci-dss'], 
                delivery_s3_bucket=conformance_bucket.bucket_name
            )

        # S3 Security Best Practices
        if 's3-best-practices' in templates:
            s3_pack = config.CfnConformancePack(
                self, "S3BestPracticesPack",
                conformance_pack_name="s3-security-best-practices",
                template_s3_uri=templates['s3-best-practices'],
                delivery_s3_bucket=conformance_bucket.bucket_name
            )

        # Outputs
        CfnOutput(self, "ConformancePacksBucketOutput",
            value=bucket_name,
            description="S3 bucket containing conformance pack templates"
        )

        print("✅ Conformance packs configured!")