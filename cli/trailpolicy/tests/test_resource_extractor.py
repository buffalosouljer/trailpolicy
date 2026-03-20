"""Tests for resource_extractor module."""

from trailpolicy.core.event_parser import ParsedEvent
from trailpolicy.core.resource_extractor import extract_resources


class TestResourceExtractor:
    def test_s3_bucket_and_key(self):
        """S3 events extract bucket ARN and object ARN from requestParameters."""
        events = [
            ParsedEvent(
                event_source="s3.amazonaws.com",
                event_name="GetObject",
                request_parameters={"bucketName": "my-bucket", "key": "path/file.txt"},
                aws_region="us-east-1",
                account_id="123456789012",
            )
        ]
        result = extract_resources(events, partition="aws")
        assert "arn:aws:s3:::my-bucket" in result[0].resources
        assert "arn:aws:s3:::my-bucket/path/file.txt" in result[0].resources

    def test_s3_bucket_only(self):
        """S3 bucket-level operations get bucket ARN and wildcard."""
        events = [
            ParsedEvent(
                event_source="s3.amazonaws.com",
                event_name="ListBucket",
                request_parameters={"bucketName": "my-bucket"},
                aws_region="us-east-1",
                account_id="123456789012",
            )
        ]
        result = extract_resources(events, partition="aws")
        assert "arn:aws:s3:::my-bucket" in result[0].resources
        assert "arn:aws:s3:::my-bucket/*" in result[0].resources

    def test_dynamodb_table(self):
        """DynamoDB events extract table ARN from requestParameters."""
        events = [
            ParsedEvent(
                event_source="dynamodb.amazonaws.com",
                event_name="GetItem",
                request_parameters={"tableName": "MyTable"},
                aws_region="us-east-1",
                account_id="123456789012",
            )
        ]
        result = extract_resources(events, partition="aws")
        assert result[0].resources == [
            "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable"
        ]

    def test_lambda_function_name(self):
        """Lambda events extract function ARN from functionName."""
        events = [
            ParsedEvent(
                event_source="lambda.amazonaws.com",
                event_name="Invoke",
                request_parameters={"functionName": "my-func"},
                aws_region="us-east-1",
                account_id="123456789012",
            )
        ]
        result = extract_resources(events, partition="aws")
        assert result[0].resources == [
            "arn:aws:lambda:us-east-1:123456789012:function:my-func"
        ]

    def test_lambda_function_arn(self):
        """Lambda events with full ARN use it directly."""
        arn = "arn:aws:lambda:us-east-1:123456789012:function:my-func"
        events = [
            ParsedEvent(
                event_source="lambda.amazonaws.com",
                event_name="Invoke",
                request_parameters={"functionName": arn},
                aws_region="us-east-1",
                account_id="123456789012",
            )
        ]
        result = extract_resources(events, partition="aws")
        assert result[0].resources == [arn]

    def test_sqs_queue_url(self):
        """SQS events extract queue ARN from queueUrl."""
        events = [
            ParsedEvent(
                event_source="sqs.amazonaws.com",
                event_name="SendMessage",
                request_parameters={
                    "queueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/my-queue"
                },
                aws_region="us-east-1",
                account_id="123456789012",
            )
        ]
        result = extract_resources(events, partition="aws")
        assert result[0].resources == [
            "arn:aws:sqs:us-east-1:123456789012:my-queue"
        ]

    def test_existing_resources_preserved(self):
        """Events with resources already populated should keep them."""
        events = [
            ParsedEvent(
                event_source="kms.amazonaws.com",
                event_name="Decrypt",
                resources=["arn:aws:kms:us-east-1:123456789012:key/abc-123"],
                aws_region="us-east-1",
                account_id="123456789012",
            )
        ]
        result = extract_resources(events, partition="aws")
        assert result[0].resources == [
            "arn:aws:kms:us-east-1:123456789012:key/abc-123"
        ]

    def test_no_params_gets_wildcard(self):
        """Events with no extractable resources get wildcard."""
        events = [
            ParsedEvent(
                event_source="ec2.amazonaws.com",
                event_name="DescribeInstances",
                request_parameters=None,
                aws_region="us-east-1",
                account_id="123456789012",
            )
        ]
        result = extract_resources(events, partition="aws")
        assert result[0].resources == ["*"]

    def test_deduplicates_resources(self):
        """Duplicate ARNs should be removed."""
        events = [
            ParsedEvent(
                event_source="kms.amazonaws.com",
                event_name="Decrypt",
                resources=[
                    "arn:aws:kms:us-east-1:123456789012:key/abc",
                    "arn:aws:kms:us-east-1:123456789012:key/abc",
                ],
                aws_region="us-east-1",
                account_id="123456789012",
            )
        ]
        result = extract_resources(events, partition="aws")
        assert len(result[0].resources) == 1

    def test_govcloud_partition(self):
        """GovCloud partition should be reflected in generated ARNs."""
        events = [
            ParsedEvent(
                event_source="s3.amazonaws.com",
                event_name="GetObject",
                request_parameters={"bucketName": "gov-bucket", "key": "file.txt"},
                aws_region="us-gov-west-1",
                account_id="123456789012",
            )
        ]
        result = extract_resources(events, partition="aws-us-gov")
        assert "arn:aws-us-gov:s3:::gov-bucket" in result[0].resources

    def test_unhandled_service_with_params_gets_wildcard(self):
        """Services with params but no extractor should get wildcard resources."""
        events = [
            ParsedEvent(
                event_source="sns.amazonaws.com",
                event_name="Publish",
                request_parameters={"topicArn": "arn:aws:sns:us-east-1:123:my-topic"},
                aws_region="us-east-1",
                account_id="123456789012",
            )
        ]
        result = extract_resources(events, partition="aws")
        assert result[0].resources == ["*"]
