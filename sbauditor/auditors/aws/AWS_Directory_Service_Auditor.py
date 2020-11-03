import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()
# import boto3 clients
ds = boto3.client("ds")
# loop through Directory Service directories
# not to be confused with weird ass cloud directory
def describe_directories(cache):
    response = cache.get("describe_directories")
    if response:
        return response
    cache["describe_directories"] = ds.describe_directories()
    return cache["describe_directories"]


@registry.register_check("ds")
def directory_service_radius_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    directories = describe_directories(cache=cache)
    myDirectories = directories["DirectoryDescriptions"]
    for directory in myDirectories:
        directoryId = str(directory["DirectoryId"])
        directoryArn = f"arn:{awsPartition}:ds:{awsRegion}:{awsAccountId}:directory/{directoryId}"
        directoryName = str(directory["Name"])
        directoryType = str(directory["Type"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if directoryType != "SimpleAD":
            try:
                # this is a passing check
                radiusCheck = str(directory["RadiusSettings"])
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": directoryArn + "/directory-service-radius-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": directoryArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[DirectoryService.1] Supported directories should have RADIUS enabled for multi-factor authentication (MFA)",
                    "Description": "Directory "
                    + directoryName
                    + " has RADIUS enabled and likely supports MFA.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on directory MFA and configuring RADIUS refer to the Multi-factor Authentication Prerequisites section of the AWS Directory Service Administration Guide",
                            "Url": "https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_getting_started_prereqs.html#prereq_mfa_ad",
                        }
                    },
                    "ProductFields": {"Product Name": "Day2SecurityBot"},
                    "Resources": [
                        {
                            "Type": "Other",
                            "Id": directoryArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"directoryName": directoryName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.AC-6",
                            "NIST SP 800-53 AC-1",
                            "NIST SP 800-53 AC-2",
                            "NIST SP 800-53 AC-3",
                            "NIST SP 800-53 AC-16",
                            "NIST SP 800-53 AC-19",
                            "NIST SP 800-53 AC-24",
                            "NIST SP 800-53 IA-1",
                            "NIST SP 800-53 IA-2",
                            "NIST SP 800-53 IA-4",
                            "NIST SP 800-53 IA-5",
                            "NIST SP 800-53 IA-8",
                            "NIST SP 800-53 PE-2",
                            "NIST SP 800-53 PS-3",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.7.1.1",
                            "ISO 27001:2013 A.9.2.1",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            except:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": directoryArn + "/directory-service-radius-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": directoryArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[DirectoryService.1] Supported directories should have RADIUS enabled for multi-factor authentication (MFA)",
                    "Description": "Directory "
                    + directoryName
                    + " does not have RADIUS enabled and thus does not support MFA. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on directory MFA and configuring RADIUS refer to the Multi-factor Authentication Prerequisites section of the AWS Directory Service Administration Guide",
                            "Url": "https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_getting_started_prereqs.html#prereq_mfa_ad",
                        }
                    },
                    "ProductFields": {"Product Name": "Day2SecurityBot"},
                    "Resources": [
                        {
                            "Type": "Other",
                            "Id": directoryArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"directoryName": directoryName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.AC-6",
                            "NIST SP 800-53 AC-1",
                            "NIST SP 800-53 AC-2",
                            "NIST SP 800-53 AC-3",
                            "NIST SP 800-53 AC-16",
                            "NIST SP 800-53 AC-19",
                            "NIST SP 800-53 AC-24",
                            "NIST SP 800-53 IA-1",
                            "NIST SP 800-53 IA-2",
                            "NIST SP 800-53 IA-4",
                            "NIST SP 800-53 IA-5",
                            "NIST SP 800-53 IA-8",
                            "NIST SP 800-53 PE-2",
                            "NIST SP 800-53 PS-3",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.7.1.1",
                            "ISO 27001:2013 A.9.2.1",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
        else:
            print("SimpleAD does not support RADIUS, skipping")
            pass


@registry.register_check("ds")
def directory_service_cloudwatch_logs_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    directories = describe_directories(cache=cache)
    myDirectories = directories["DirectoryDescriptions"]
    for directory in myDirectories:
        directoryId = str(directory["DirectoryId"])
        directoryArn = f"arn:{awsPartition}:ds:{awsRegion}:{awsAccountId}:directory/{directoryId}"
        directoryName = str(directory["Name"])
        response = ds.list_log_subscriptions(DirectoryId=directoryId)
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if str(response["LogSubscriptions"]) == "[]":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": directoryArn + "/directory-service-cloudwatch-logs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": directoryArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[DirectoryService.2] Directories should have log forwarding enabled",
                "Description": "Directory "
                + directoryName
                + " does not have log forwarding enabled. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on directory log forwarding to CloudWatch Logs refer to the Enable Log Forwarding section of the AWS Directory Service Administration Guide",
                        "Url": "https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_enable_log_forwarding.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": directoryArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"directoryName": directoryName}},
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
                "Id": directoryArn + "/directory-service-cloudwatch-logs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": directoryArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[DirectoryService.2] Directories should have log forwarding enabled",
                "Description": "Directory "
                + directoryName
                + " does not have log forwarding enabled. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on directory log forwarding to CloudWatch Logs refer to the Enable Log Forwarding section of the AWS Directory Service Administration Guide",
                        "Url": "https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_enable_log_forwarding.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": directoryArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"directoryName": directoryName}},
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
