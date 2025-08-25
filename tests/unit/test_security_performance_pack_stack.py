import aws_cdk as core
import aws_cdk.assertions as assertions

from security_performance_pack.security_performance_pack_stack import SecurityPerformancePackStack

# example tests. To run these tests, uncomment this file along with the example
# resource in security_performance_pack/security_performance_pack_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = SecurityPerformancePackStack(app, "security-performance-pack")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
