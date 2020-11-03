import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
neptune = boto3.client("neptune")


# loop through neptune instances
def describe_db_instances(cache):
    response = cache.get("describe_db_instances")
    if response:
        return response
    cache["describe_db_instances"] = neptune.describe_db_instances(
        Filters=[{"Name": "engine", "Values": ["neptune"]}]
    )
    return cache["describe_db_instances"]
    neptune_instances = describe_db_instances(cache)


@registry.register_check("neptune")
def neptune_instance_multi_az_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    neptune_instances = describe_db_instances(cache)
    for instances in neptune_instances["DBInstances"]:
        neptuneInstanceArn = str(instances["DBInstanceArn"])
        neptuneDbId = str(instances["DBInstanceIdentifier"])
        mutliAzCheck = str(instances["MultiAZ"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if mutliAzCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": neptuneInstanceArn + "/neptune-instance-ha-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Neptune.1] Neptune database instances should be configured to be highly available",
                "Description": "Neptune database instance "
                + neptuneDbId
                + " does not have Multi-AZ enabled and thus is not highly available. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune High Availability and how to configure it refer to the High Availability for Neptune section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/feature-overview-availability.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"InstanceId": neptuneDbId}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF ID.BE-5",
                        "NIST CSF PR.PT-5",
                        "NIST SP 800-53 CP-2",
                        "NIST SP 800-53 CP-11",
                        "NIST SP 800-53 SA-13",
                        "NIST SP 800-53 SA14",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": neptuneInstanceArn + "/neptune-instance-ha-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Neptune.1] Neptune database instances should be configured to be highly available",
                "Description": "Neptune database instance "
                + neptuneDbId
                + " is highly available.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune High Availability and how to configure it refer to the High Availability for Neptune section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/feature-overview-availability.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"InstanceId": neptuneDbId}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF ID.BE-5",
                        "NIST CSF PR.PT-5",
                        "NIST SP 800-53 CP-2",
                        "NIST SP 800-53 CP-11",
                        "NIST SP 800-53 SA-13",
                        "NIST SP 800-53 SA14",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding


@registry.register_check("neptune")
def neptune_instance_storage_encryption_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    neptune_instances = describe_db_instances(cache)
    for instances in neptune_instances["DBInstances"]:
        neptuneInstanceArn = str(instances["DBInstanceArn"])
        neptuneDbId = str(instances["DBInstanceIdentifier"])
        storageEncryptionCheck = str(instances["StorageEncrypted"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if storageEncryptionCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": neptuneInstanceArn + "/neptune-instance-storage-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
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
                "Title": "[Neptune.2] Neptune database instace storage should be encrypted",
                "Description": "Neptune database instance "
                + neptuneDbId
                + " does not have storage encryption enabled. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune storage encryption and how to configure it refer to the Enabling Encryption for a Neptune DB Instance section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html#encrypt-enable",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"InstanceId": neptuneDbId}},
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
                "Id": neptuneInstanceArn + "/neptune-instance-storage-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
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
                "Title": "[Neptune.2] Neptune database instace storage should be encrypted",
                "Description": "Neptune database instance "
                + neptuneDbId
                + " has storage encryption enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune storage encryption and how to configure it refer to the Enabling Encryption for a Neptune DB Instance section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html#encrypt-enable",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"InstanceId": neptuneDbId}},
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


@registry.register_check("neptune")
def neptune_instance_iam_authentication_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    neptune_instances = describe_db_instances(cache)
    for instances in neptune_instances["DBInstances"]:
        neptuneInstanceArn = str(instances["DBInstanceArn"])
        neptuneDbId = str(instances["DBInstanceIdentifier"])
        iamDbAuthCheck = str(instances["IAMDatabaseAuthenticationEnabled"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if iamDbAuthCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": neptuneInstanceArn + "/neptune-instance-iam-db-auth-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Neptune.3] Neptune database instaces storage should use IAM Database Authentication",
                "Description": "Neptune database instance "
                + neptuneDbId
                + " does not use IAM Database Authentication. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune IAM Database Authentication and how to configure it refer to the Neptune Database Authentication Using IAM section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"InstanceId": neptuneDbId}},
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
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": neptuneInstanceArn + "/neptune-instance-iam-db-auth-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
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
                "Title": "[Neptune.3] Neptune database instaces storage should use IAM Database Authentication",
                "Description": "Neptune database instance "
                + neptuneDbId
                + " uses IAM Database Authentication.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune IAM Database Authentication and how to configure it refer to the Neptune Database Authentication Using IAM section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"InstanceId": neptuneDbId}},
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


@registry.register_check("neptune")
def neptune_cluster_parameter_ssl_enforcement_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    neptune_instances = describe_db_instances(cache)
    response = neptune.describe_db_cluster_parameter_groups()
    for parametergroup in response["DBClusterParameterGroups"]:
        parameterGroupName = str(parametergroup["DBClusterParameterGroupName"])
        parameterGroupArn = str(parametergroup["DBClusterParameterGroupArn"])
        response = neptune.describe_db_cluster_parameters(
            DBClusterParameterGroupName=parameterGroupName
        )
        for parameters in response["Parameters"]:
            if str(parameters["ParameterName"]) == "neptune_enforce_ssl":
                sslEnforcementCheck = str(parameters["ParameterValue"])
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                if sslEnforcementCheck == "0":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": parameterGroupArn
                        + "/neptune-cluster-param-group-ssl-enforcement-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": parameterGroupArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[Neptune.4] Neptune cluster parameter groups should enforce SSL connections to Neptune databases",
                        "Description": "Neptune cluster parameter group "
                        + parameterGroupName
                        + " does not enforce SSL connections. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on enforcing SSL/HTTPS connections to Neptune instances refer to the Encryption in Transit: Connecting to Neptune Using SSL/HTTPS section of the Amazon Neptune User Guide.",
                                "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/security-ssl.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "Other",
                                "Id": parameterGroupArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {"ParameterGroupName": parameterGroupName}},
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF PR.DS-2",
                                "NIST SP 800-53 SC-8",
                                "NIST SP 800-53 SC-11",
                                "NIST SP 800-53 SC-12",
                                "AICPA TSC CC6.1",
                                "ISO 27001:2013 A.8.2.3",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1",
                                "ISO 27001:2013 A.13.2.3",
                                "ISO 27001:2013 A.14.1.2",
                                "ISO 27001:2013 A.14.1.3",
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": parameterGroupArn
                        + "/neptune-cluster-param-group-ssl-enforcement-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": parameterGroupArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[Neptune.4] Neptune cluster parameter groups should enforce SSL connections to Neptune databases",
                        "Description": "Neptune cluster parameter group "
                        + parameterGroupName
                        + " enforces SSL connections.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on enforcing SSL/HTTPS connections to Neptune instances refer to the Encryption in Transit: Connecting to Neptune Using SSL/HTTPS section of the Amazon Neptune User Guide.",
                                "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/security-ssl.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "Other",
                                "Id": parameterGroupArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {"ParameterGroupName": parameterGroupName}},
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF PR.DS-2",
                                "NIST SP 800-53 SC-8",
                                "NIST SP 800-53 SC-11",
                                "NIST SP 800-53 SC-12",
                                "AICPA TSC CC6.1",
                                "ISO 27001:2013 A.8.2.3",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1",
                                "ISO 27001:2013 A.13.2.3",
                                "ISO 27001:2013 A.14.1.2",
                                "ISO 27001:2013 A.14.1.3",
                            ],
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
            else:
                pass


@registry.register_check("neptune")
def neptune_cluster_parameter_audit_log_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    neptune_instances = describe_db_instances(cache)
    response = neptune.describe_db_cluster_parameter_groups()
    for parametergroup in response["DBClusterParameterGroups"]:
        parameterGroupName = str(parametergroup["DBClusterParameterGroupName"])
        parameterGroupArn = str(parametergroup["DBClusterParameterGroupArn"])
        response = neptune.describe_db_cluster_parameters(
            DBClusterParameterGroupName=parameterGroupName
        )
        for parameters in response["Parameters"]:
            if str(parameters["ParameterName"]) == "neptune_enable_audit_log":
                auditLogCheck = str(parameters["ParameterValue"])
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                if auditLogCheck == "0":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": parameterGroupArn
                        + "/neptune-cluster-param-group-audit-logging-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": parameterGroupArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[Neptune.5] Neptune cluster parameter groups should enforce audit logging for Neptune databases",
                        "Description": "Neptune cluster parameter group "
                        + parameterGroupName
                        + " does not enforce audit logging. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on audit logging for Neptune instances refer to the Enabling Neptune Audit Logs section of the Amazon Neptune User Guide.",
                                "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html#auditing-enable",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "Other",
                                "Id": parameterGroupArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {"ParameterGroupName": parameterGroupName}},
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
                        "Id": parameterGroupArn
                        + "/neptune-cluster-param-group-audit-logging-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": parameterGroupArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[Neptune.5] Neptune cluster parameter groups should enforce audit logging for Neptune databases",
                        "Description": "Neptune cluster parameter group "
                        + parameterGroupName
                        + " enforces audit logging.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on audit logging for Neptune instances refer to the Enabling Neptune Audit Logs section of the Amazon Neptune User Guide.",
                                "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html#auditing-enable",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "Other",
                                "Id": parameterGroupArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {"ParameterGroupName": parameterGroupName}},
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
            else:
                pass
