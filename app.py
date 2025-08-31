#!/usr/bin/env python3
from aws_cdk import App, Stack

from security_performance_pack.security_performance_pack_stack import SecurityPerformancePackStack
from security_performance_pack.data_lake_stack import SecurityDataLakeStack

import subprocess
import os

# --- Run conformance pack downloader before synth/deploy ---
print("⬇️  Downloading and uploading conformance packs to S3...")
subprocess.run(
    ["python", "scripts/download_conformance_packs.py"],
    check=True
)

print("✅ Conformance packs uploaded")

# --- CDK App ---
app = App()

# Deploy security foundation first
security_stack = SecurityPerformancePackStack(app, "SecurityPerformancePackStack")

# Deploy data lake (depends on security foundation)
data_lake_stack = SecurityDataLakeStack(app, "SecurityDataLakeStack")

# Finalize app synth
app.synth()