import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()
# create boto3 clients
ec2 = boto3.client("ec2")
ssm = boto3.client("ssm")

# loop through ec2 instances
def describe_instances(cache):
    response = cache.get("describe_instances")
    if response:
        return response
    cache["describe_instances"] = ec2.describe_instances(DryRun=False, MaxResults=1000)
    return cache["describe_instances"]


@registry.register_check("ec2")
def ec2_instance_ssm_managed_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_instances(cache)
    myEc2InstanceReservations = response["Reservations"]
    for reservations in myEc2InstanceReservations:
        for instances in reservations["Instances"]:
            instanceId = str(instances["InstanceId"])
            instanceArn = (
                f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
            )
            instanceType = str(instances["InstanceType"])
            instanceImage = str(instances["ImageId"])
            instanceVpc = str(instances["VpcId"])
            instanceSubnet = str(instances["SubnetId"])
            instanceLaunchedAt = str(instances["LaunchTime"])
            try:
                response = ssm.describe_instance_information(
                    InstanceInformationFilterList=[
                        {"key": "InstanceIds", "valueSet": [instanceId]},
                    ]
                )
                # ISO Time
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                if str(response["InstanceInformationList"]) == "[]":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": instanceArn + "/ec2-managed-by-ssm-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": instanceArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[EC2-SSM.1] EC2 Instances should be managed by Systems Manager",
                        "Description": "EC2 Instance "
                        + instanceId
                        + " is not managed by Systems Manager. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "To learn how to configure Systems Manager and associated instances refer to the Setting Up AWS Systems Manager section of the AWS Systems Manager User Guide",
                                "Url": "https://docs.aws.amazon.com/en_us/systems-manager/latest/userguide/systems-manager-setting-up.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsEc2Instance",
                                "Id": instanceArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2Instance": {
                                        "Type": instanceType,
                                        "ImageId": instanceImage,
                                        "VpcId": instanceVpc,
                                        "SubnetId": instanceSubnet,
                                        "LaunchedAt": instanceLaunchedAt,
                                    }
                                },
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
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": instanceArn + "/ec2-managed-by-ssm-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": instanceArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[EC2-SSM.1] EC2 Instances should be managed by Systems Manager",
                        "Description": "EC2 Instance "
                        + instanceId
                        + " is managed by Systems Manager.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "To learn how to configure Systems Manager and associated instances refer to the Setting Up AWS Systems Manager section of the AWS Systems Manager User Guide",
                                "Url": "https://docs.aws.amazon.com/en_us/systems-manager/latest/userguide/systems-manager-setting-up.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsEc2Instance",
                                "Id": instanceArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2Instance": {
                                        "Type": instanceType,
                                        "ImageId": instanceImage,
                                        "VpcId": instanceVpc,
                                        "SubnetId": instanceSubnet,
                                        "LaunchedAt": instanceLaunchedAt,
                                    }
                                },
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
            except Exception as e:
                print(e)


@registry.register_check("ec2")
def ssm_instace_agent_update_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_instances(cache)
    myEc2InstanceReservations = response["Reservations"]
    for reservations in myEc2InstanceReservations:
        for instances in reservations["Instances"]:
            instanceId = str(instances["InstanceId"])
            instanceArn = (
                f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
            )
            instanceType = str(instances["InstanceType"])
            instanceImage = str(instances["ImageId"])
            instanceVpc = str(instances["VpcId"])
            instanceSubnet = str(instances["SubnetId"])
            instanceLaunchedAt = str(instances["LaunchTime"])
            response = ssm.describe_instance_information()
            myManagedInstances = response["InstanceInformationList"]
            for instances in myManagedInstances:
                latestVersionCheck = str(instances["IsLatestVersion"])
                # ISO Time
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                if latestVersionCheck == "False":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": instanceArn + "/ec2-ssm-agent-latest-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": instanceArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[EC2-SSM.2] EC2 Instances managed by Systems Manager should have the latest SSM Agent installed",
                        "Description": "EC2 Instance "
                        + instanceId
                        + " does not have the latest SSM Agent installed. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on automating updates to the SSM Agent refer to the Automate Updates to SSM Agent section of the AWS Systems Manager User Guide",
                                "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-automatic-updates.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsEc2Instance",
                                "Id": instanceArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2Instance": {
                                        "Type": instanceType,
                                        "ImageId": instanceImage,
                                        "VpcId": instanceVpc,
                                        "SubnetId": instanceSubnet,
                                        "LaunchedAt": instanceLaunchedAt,
                                    }
                                },
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
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": instanceArn + "/ec2-ssm-agent-latest-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": instanceArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[EC2-SSM.2] EC2 Instances managed by Systems Manager should have the latest SSM Agent installed",
                        "Description": "EC2 Instance "
                        + instanceId
                        + " has the latest SSM Agent installed.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on automating updates to the SSM Agent refer to the Automate Updates to SSM Agent section of the AWS Systems Manager User Guide",
                                "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-automatic-updates.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsEc2Instance",
                                "Id": instanceArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2Instance": {
                                        "Type": instanceType,
                                        "ImageId": instanceImage,
                                        "VpcId": instanceVpc,
                                        "SubnetId": instanceSubnet,
                                        "LaunchedAt": instanceLaunchedAt,
                                    }
                                },
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


@registry.register_check("ec2")
def ssm_instance_association_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_instances(cache)
    myEc2InstanceReservations = response["Reservations"]
    for reservations in myEc2InstanceReservations:
        for instances in reservations["Instances"]:
            instanceId = str(instances["InstanceId"])
            instanceArn = (
                f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
            )
            instanceType = str(instances["InstanceType"])
            instanceImage = str(instances["ImageId"])
            instanceVpc = str(instances["VpcId"])
            instanceSubnet = str(instances["SubnetId"])
            instanceLaunchedAt = str(instances["LaunchTime"])
            response = ssm.describe_instance_information()
            myManagedInstances = response["InstanceInformationList"]
            for instances in myManagedInstances:
                associationStatusCheck = str(instances["AssociationStatus"])
                # ISO Time
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                if associationStatusCheck != "Success":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": instanceArn + "/ec2-ssm-association-success-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": instanceArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[EC2-SSM.3] EC2 Instances managed by Systems Manager should have a successful Association status",
                        "Description": "EC2 Instance "
                        + instanceId
                        + " does not have a successful Association status. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on Systems Manager Associations refer to the Working with Associations in Systems Manager section of the AWS Systems Manager User Guide",
                                "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-associations.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsEc2Instance",
                                "Id": instanceArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2Instance": {
                                        "Type": instanceType,
                                        "ImageId": instanceImage,
                                        "VpcId": instanceVpc,
                                        "SubnetId": instanceSubnet,
                                        "LaunchedAt": instanceLaunchedAt,
                                    }
                                },
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
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": instanceArn + "/ec2-ssm-association-success-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": instanceArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[EC2-SSM.3] EC2 Instances managed by Systems Manager should have a successful Association status",
                        "Description": "EC2 Instance "
                        + instanceId
                        + " has a successful Association status.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on Systems Manager Associations refer to the Working with Associations in Systems Manager section of the AWS Systems Manager User Guide",
                                "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-associations.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsEc2Instance",
                                "Id": instanceArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2Instance": {
                                        "Type": instanceType,
                                        "ImageId": instanceImage,
                                        "VpcId": instanceVpc,
                                        "SubnetId": instanceSubnet,
                                        "LaunchedAt": instanceLaunchedAt,
                                    }
                                },
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


@registry.register_check("ec2")
def ssm_instance_patch_state_state(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_instances(cache)
    myEc2InstanceReservations = response["Reservations"]
    for reservations in myEc2InstanceReservations:
        for instances in reservations["Instances"]:
            instanceId = str(instances["InstanceId"])
            instanceArn = (
                f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
            )
            instanceType = str(instances["InstanceType"])
            instanceImage = str(instances["ImageId"])
            instanceVpc = str(instances["VpcId"])
            instanceSubnet = str(instances["SubnetId"])
            instanceLaunchedAt = str(instances["LaunchTime"])
            response = ssm.describe_instance_information()
            try:
                response = ssm.describe_instance_patch_states(InstanceIds=[instanceId])
                patchStatesCheck = str(response["InstancePatchStates"])
                # ISO Time
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                if patchStatesCheck == "[]":
                    print("no patch info")
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": instanceArn + "/ec2-patch-manager-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": instanceArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[EC2-SSM.4] EC2 Instances managed by Systems Manager should have the latest patches installed by Patch Manager",
                        "Description": "EC2 Instance "
                        + instanceId
                        + " does not have any patch information recorded and is likely not managed by Patch Manager. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on Patch Manager refer to the AWS Systems Manager Patch Manager section of the AWS Systems Manager User Guide",
                                "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsEc2Instance",
                                "Id": instanceArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2Instance": {
                                        "Type": instanceType,
                                        "ImageId": instanceImage,
                                        "VpcId": instanceVpc,
                                        "SubnetId": instanceSubnet,
                                        "LaunchedAt": instanceLaunchedAt,
                                    }
                                },
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
                else:
                    patchStates = response["InstancePatchStates"]
                    for patches in patchStates:
                        failedPatchCheck = str(patches["FailedCount"])
                        missingPatchCheck = str(patches["MissingCount"])
                        if failedPatchCheck != "0" or missingPatchCheck != "0":
                            finding = {
                                "SchemaVersion": "2018-10-08",
                                "Id": instanceArn + "/ec2-patch-manager-check",
                                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                "GeneratorId": instanceArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [
                                    "Software and Configuration Checks/AWS Security Best Practices"
                                ],
                                "FirstObservedAt": iso8601Time,
                                "CreatedAt": iso8601Time,
                                "UpdatedAt": iso8601Time,
                                "Severity": {"Label": "MEDIUM"},
                                "Confidence": 99,
                                "Title": "[EC2-SSM.4] EC2 Instances managed by Systems Manager should have the latest patches installed by Patch Manager",
                                "Description": "EC2 Instance "
                                + instanceId
                                + " is missing patches or has patches that failed to apply. Refer to the remediation instructions if this configuration is not intended",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For information on Patch Manager refer to the AWS Systems Manager Patch Manager section of the AWS Systems Manager User Guide",
                                        "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html",
                                    }
                                },
                                "ProductFields": {"Product Name": "Day2SecurityBot"},
                                "Resources": [
                                    {
                                        "Type": "AwsEc2Instance",
                                        "Id": instanceArn,
                                        "Partition": awsPartition,
                                        "Region": awsRegion,
                                        "Details": {
                                            "AwsEc2Instance": {
                                                "Type": instanceType,
                                                "ImageId": instanceImage,
                                                "VpcId": instanceVpc,
                                                "SubnetId": instanceSubnet,
                                                "LaunchedAt": instanceLaunchedAt,
                                            }
                                        },
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
                        else:
                            finding = {
                                "SchemaVersion": "2018-10-08",
                                "Id": instanceArn + "/ec2-patch-manager-check",
                                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                "GeneratorId": instanceArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [
                                    "Software and Configuration Checks/AWS Security Best Practices"
                                ],
                                "FirstObservedAt": iso8601Time,
                                "CreatedAt": iso8601Time,
                                "UpdatedAt": iso8601Time,
                                "Severity": {"Label": "INFORMATIONAL"},
                                "Confidence": 99,
                                "Title": "[EC2-SSM.4] EC2 Instances managed by Systems Manager should have the latest patches installed by Patch Manager",
                                "Description": "EC2 Instance "
                                + instanceId
                                + " has the latest patches installed by Patch Manager.",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For information on Patch Manager refer to the AWS Systems Manager Patch Manager section of the AWS Systems Manager User Guide",
                                        "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html",
                                    }
                                },
                                "ProductFields": {"Product Name": "Day2SecurityBot"},
                                "Resources": [
                                    {
                                        "Type": "AwsEc2Instance",
                                        "Id": instanceArn,
                                        "Partition": awsPartition,
                                        "Region": awsRegion,
                                        "Details": {
                                            "AwsEc2Instance": {
                                                "Type": instanceType,
                                                "ImageId": instanceImage,
                                                "VpcId": instanceVpc,
                                                "SubnetId": instanceSubnet,
                                                "LaunchedAt": instanceLaunchedAt,
                                            }
                                        },
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
            except Exception as e:
                print(e)
