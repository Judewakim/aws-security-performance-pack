#!/usr/bin/env python3
"""
Downloads AWS managed conformance pack templates and uploads them to S3
"""
import boto3
import requests
import os
import json
from pathlib import Path

# AWS managed conformance pack templates (updated URLs - verified working)
CONFORMANCE_PACKS = {
    'aws-well-architected-security': {
        'url': 'https://raw.githubusercontent.com/awslabs/aws-config-rules/master/aws-config-conformance-packs/Operational-Best-Practices-for-AWS-Well-Architected-Security-Pillar.yaml',
        'description': 'AWS Well-Architected Security Pillar'
    },
    'cis-aws-foundations-benchmark': {
        'url': 'https://raw.githubusercontent.com/awslabs/aws-config-rules/master/aws-config-conformance-packs/Operational-Best-Practices-for-CIS-AWS-v1.4-Level1.yaml', 
        'description': 'CIS AWS Foundations Benchmark v1.4 Level 1'
    },
    'nist-800-53': {
        'url': 'https://raw.githubusercontent.com/awslabs/aws-config-rules/master/aws-config-conformance-packs/Operational-Best-Practices-for-NIST-800-53-rev-5.yaml',
        'description': 'NIST 800-53 Rev 5'
    },
    'pci-dss': {
        'url': 'https://raw.githubusercontent.com/awslabs/aws-config-rules/master/aws-config-conformance-packs/Operational-Best-Practices-for-PCI-DSS.yaml',
        'description': 'PCI DSS 3.2.1'
    },
    'hipaa-security': {
        'url': 'https://raw.githubusercontent.com/awslabs/aws-config-rules/master/aws-config-conformance-packs/Operational-Best-Practices-for-HIPAA-Security.yaml',
        'description': 'HIPAA Security Requirements'
    }
}

def download_and_upload_conformance_packs():
    """Download conformance pack templates and upload to S3"""
    
    # Get S3 client
    s3_client = boto3.client('s3')
    
    # Get account ID and region
    sts_client = boto3.client('sts')
    account_id = sts_client.get_caller_identity()['Account']
    region = boto3.Session().region_name
    
    # Create bucket name (this should match your CDK stack)
    bucket_name = f"security-conformance-packs-{account_id}-{region}"
    
    print(f"🪣 Creating S3 bucket: {bucket_name}")
    
    # Create S3 bucket for conformance packs
    try:
        if region == 'us-east-1':
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        print(f"✅ Created bucket: {bucket_name}")
    except s3_client.exceptions.BucketAlreadyExists:
        print(f"✅ Bucket already exists: {bucket_name}")
    except Exception as e:
        print(f"❌ Error creating bucket: {e}")
        return None
    
    # Enable versioning and encryption
    try:
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                }]
            }
        )
        print("✅ Enabled versioning and encryption")
    except Exception as e:
        print(f"⚠️  Warning: Could not enable versioning/encryption: {e}")
    
    # Create local directory for downloads
    os.makedirs('conformance-packs', exist_ok=True)
    
    uploaded_templates = {}
    
    # Download and upload each conformance pack
    for pack_name, pack_info in CONFORMANCE_PACKS.items():
        print(f"\n📥 Downloading {pack_name}...")
        
        try:
            # Download the template
            response = requests.get(pack_info['url'], timeout=30)
            response.raise_for_status()
            
            # Save locally first
            local_file = f"conformance-packs/{pack_name}.yaml"
            with open(local_file, 'w') as f:
                f.write(response.text)
            print(f"✅ Downloaded to {local_file}")
            
            # Upload to S3
            s3_key = f"conformance-packs/{pack_name}.yaml"
            s3_client.upload_file(
                local_file, 
                bucket_name, 
                s3_key,
                ExtraArgs={
                    'ContentType': 'text/yaml',
                    'Metadata': {
                        'description': pack_info['description'],
                        'source': pack_info['url']
                    }
                }
            )
            
            s3_uri = f"s3://{bucket_name}/{s3_key}"
            uploaded_templates[pack_name] = s3_uri
            print(f"✅ Uploaded to {s3_uri}")
            
        except Exception as e:
            print(f"❌ Error downloading {pack_name}: {e}")
            continue
    
    # Save the S3 URIs for use in CDK
    output_file = 'conformance-pack-uris.json'
    with open(output_file, 'w') as f:
        json.dump({
            'bucket_name': bucket_name,
            'templates': uploaded_templates
        }, f, indent=2)
    
    print(f"\n✅ All done! S3 URIs saved to {output_file}")
    print(f"📍 Bucket: {bucket_name}")
    print("📄 Templates uploaded:")
    for name, uri in uploaded_templates.items():
        print(f"   {name}: {uri}")
    
    return bucket_name, uploaded_templates

if __name__ == "__main__":
    download_and_upload_conformance_packs()