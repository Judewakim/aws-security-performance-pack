#!/usr/bin/env python3
"""
AWS Security Foundation - Product 1
Production-ready security baseline for AWS accounts
"""

from aws_cdk import App
from security_foundation_stack import SecurityFoundationStack

app = App()

# Deploy the security foundation
SecurityFoundationStack(app, "AWSSecurityFoundation")

app.synth()