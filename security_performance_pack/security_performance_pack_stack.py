from aws_cdk import (
    Stack,
    aws_s3 as s3,
    RemovalPolicy,
)
from constructs import Construct

class SecurityPerformancePackStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Test S3 bucket
        test_bucket = s3.Bucket(self, "TestBucket",
            bucket_name=f"security-test-{self.account}-{self.region}",
            auto_delete_objects=True,
            removal_policy=RemovalPolicy.DESTROY
        )