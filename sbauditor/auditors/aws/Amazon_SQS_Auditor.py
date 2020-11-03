import datetime
from dateutil import parser

import boto3

from check_register import CheckRegister

registry = CheckRegister()
sqs = boto3.client("sqs")
cloudwatch = boto3.client("cloudwatch")


@registry.register_check("sqs")
def sqs_old_message_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = sqs.list_queues()
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for queueUrl in response["QueueUrls"]:
        queueName = queueUrl.rsplit("/", 1)[-1]
        attributes = sqs.get_queue_attributes(
            QueueUrl=queueUrl, AttributeNames=["MessageRetentionPeriod", "QueueArn"]
        )
        messageRetention = attributes["Attributes"]["MessageRetentionPeriod"]
        queueArn = attributes["Attributes"]["QueueArn"]
        metricResponse = cloudwatch.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "m1",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/SQS",
                            "MetricName": "ApproximateAgeOfOldestMessage",
                            "Dimensions": [{"Name": "QueueName", "Value": queueName}],
                        },
                        "Period": 3600,
                        "Stat": "Maximum",
                        "Unit": "Seconds",
                    },
                },
            ],
            StartTime=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1),
            EndTime=datetime.datetime.now(datetime.timezone.utc),
        )
        metrics = metricResponse["MetricDataResults"]
        counter = 0
        fail = False
        for metric in metrics:
            for value in metric["Values"]:
                if value > int(messageRetention) * 0.8:
                    counter += 1
                if counter > 2:
                    fail = True
                    break
        if not fail:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": queueArn + "/sqs-old-message-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": queueArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[SQS.1] SQS messages should not be older than 80 percent of message retention",
                "Description": "SQS queue "
                + queueName
                + " has not had at least 3 messages waiting for longer than 80 percent of the message retention.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on best practices for SQS queue messages refer to the Quotas related to messages section of the Amazon SQS Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-quotas.html#quotas-messages",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsSQS",
                        "Id": queueArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF ID.AM-2",
                        "NIST SP 800-53 CM-8",
                        "NIST SP 800-53 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": queueArn + "/sqs-old-message-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": queueArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[SQS.1] SQS messages should not be older than 80 percent of message retention",
                "Description": "SQS queue "
                + queueName
                + " has had at least 3 messages waiting for longer than 80 percent of the message retention.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on best practices for SQS queue messages refer to the Quotas related to messages section of the Amazon SQS Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-quotas.html#quotas-messages",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsSQS",
                        "Id": queueArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF ID.AM-2",
                        "NIST SP 800-53 CM-8",
                        "NIST SP 800-53 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
