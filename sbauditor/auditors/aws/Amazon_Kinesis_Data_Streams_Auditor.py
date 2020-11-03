import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
kinesis = boto3.client("kinesis")


# loop through kinesis streams
def list_streams(cache):
    response = cache.get("list_streams")
    if response:
        return response
    cache["list_streams"] = kinesis.list_streams(Limit=100)
    return cache["list_streams"]


@registry.register_check("sns")
def kinesis_stream_encryption_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = list_streams(cache)
    myKinesisStreams = response["StreamNames"]
    for streams in myKinesisStreams:
        response = kinesis.describe_stream(StreamName=streams)
        streamArn = str(response["StreamDescription"]["StreamARN"])
        streamName = str(response["StreamDescription"]["StreamName"])
        streamEncryptionCheck = str(response["StreamDescription"]["EncryptionType"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if streamEncryptionCheck == "NONE":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": streamArn + "/kinesis-streams-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": streamArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Kinesis.1] Kinesis Data Streams should be encrypted",
                "Description": "Kinesis data stream "
                + streamName
                + " is not encrypted. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Kinesis Data Stream encryption refer to the How Do I Get Started with Server-Side Encryption? section of the Amazon Kinesis Data Streams Developer Guide",
                        "Url": "https://docs.aws.amazon.com/streams/latest/dev/getting-started-with-sse.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsKinesisStream",
                        "Id": streamArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"StreamName": streamName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-1",
                        "NIST SP 800-53 MP-8",
                        "NIST SP 800-53 SC-12",
                        "NIST SP 800-53 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": streamArn + "/kinesis-streams-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": streamArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Kinesis.1] Kinesis Data Streams should be encrypted",
                "Description": "Kinesis data stream " + streamName + " is encrypted.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Kinesis Data Stream encryption refer to the How Do I Get Started with Server-Side Encryption? section of the Amazon Kinesis Data Streams Developer Guide",
                        "Url": "https://docs.aws.amazon.com/streams/latest/dev/getting-started-with-sse.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsKinesisStream",
                        "Id": streamArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"StreamName": streamName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-1",
                        "NIST SP 800-53 MP-8",
                        "NIST SP 800-53 SC-12",
                        "NIST SP 800-53 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding


@registry.register_check("sns")
def kinesis_enhanced_monitoring_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = list_streams(cache)
    myKinesisStreams = response["StreamNames"]
    for streams in myKinesisStreams:
        response = kinesis.describe_stream(StreamName=streams)
        streamArn = str(response["StreamDescription"]["StreamARN"])
        streamName = str(response["StreamDescription"]["StreamName"])
        streamEnhancedMonitoring = response["StreamDescription"]["EnhancedMonitoring"]
        for enhancedmonitors in streamEnhancedMonitoring:
            shardLevelMetricCheck = str(enhancedmonitors["ShardLevelMetrics"])
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if shardLevelMetricCheck == "[]":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": streamArn + "/kinesis-streams-enhanced-monitoring-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": streamArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[Kinesis.2] Business-critical Kinesis Data Streams should have detailed monitoring configured",
                    "Description": "Kinesis data stream "
                    + streamName
                    + " does not have detailed monitoring configured, detailed monitoring allows shard-level metrics to be delivered every minute at additional cost. Business-critical streams should be considered for this configuration. Refer to the remediation instructions for information on this configuration",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Kinesis Data Stream enhanced monitoring refer to the Monitoring the Amazon Kinesis Data Streams Service with Amazon CloudWatch section of the Amazon Kinesis Data Streams Developer Guide",
                            "Url": "https://docs.aws.amazon.com/streams/latest/dev/monitoring-with-cloudwatch.html",
                        }
                    },
                    "ProductFields": {"Product Name": "Day2SecurityBot"},
                    "Resources": [
                        {
                            "Type": "AwsKinesisStream",
                            "Id": streamArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"StreamName": streamName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF DE.AE-3",
                            "NIST SP 800-53 AU-6",
                            "NIST SP 800-53 CA-7",
                            "NIST SP 800-53 IR-4",
                            "NIST SP 800-53 IR-5",
                            "NIST SP 800-53 IR-8",
                            "NIST SP 800-53 SI-4",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.7",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": streamArn + "/kinesis-streams-enhanced-monitoring-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": streamArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[Kinesis.2] Business-critical Kinesis Data Streams should have detailed monitoring configured",
                    "Description": "Kinesis data stream "
                    + streamName
                    + " has detailed monitoring configured.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Kinesis Data Stream enhanced monitoring refer to the Monitoring the Amazon Kinesis Data Streams Service with Amazon CloudWatch section of the Amazon Kinesis Data Streams Developer Guide",
                            "Url": "https://docs.aws.amazon.com/streams/latest/dev/monitoring-with-cloudwatch.html",
                        }
                    },
                    "ProductFields": {"Product Name": "Day2SecurityBot"},
                    "Resources": [
                        {
                            "Type": "AwsKinesisStream",
                            "Id": streamArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"StreamName": streamName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF DE.AE-3",
                            "NIST SP 800-53 AU-6",
                            "NIST SP 800-53 CA-7",
                            "NIST SP 800-53 IR-4",
                            "NIST SP 800-53 IR-5",
                            "NIST SP 800-53 IR-8",
                            "NIST SP 800-53 SI-4",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.7",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
