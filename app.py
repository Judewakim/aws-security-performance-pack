#!/usr/bin/env python3
import os
import aws_cdk as cdk
from security_performance_pack.security_performance_pack_stack import SecurityPerformancePackStack
from security_performance_pack.data_lake_stack import SecurityDataLakeStack

app = cdk.App()

# Deploy security foundation first
security_stack = SecurityPerformancePackStack(app, "SecurityPerformancePackStack")

# Deploy data lake (depends on security foundation)
data_lake_stack = SecurityDataLakeStack(app, "SecurityDataLakeStack")

app.synth()