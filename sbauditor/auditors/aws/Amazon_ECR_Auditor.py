import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
ecr = boto3.client("ecr")
# loop through ECR repos
def describe_repositories(cache):
    response = cache.get("describe_repositories")
    if response:
        return response
    cache["describe_repositories"] = ecr.describe_repositories(maxResults=1000)
    return cache["describe_repositories"]


@registry.register_check("ecr")
def ecr_repo_vuln_scan_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_repositories(cache)
    myRepos = response["repositories"]
    for repo in myRepos:
        repoArn = str(repo["repositoryArn"])
        repoName = str(repo["repositoryName"])
        scanningConfig = str(repo["imageScanningConfiguration"]["scanOnPush"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if scanningConfig == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": repoArn + "/ecr-no-scan",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": repoArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[ECR.1] ECR repositories should be configured to scan images on push",
                "Description": "ECR repository "
                + repoName
                + " is not configured to scan images on push. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your repository should be configured to scan on push refer to the Image Scanning section in the Amazon ECR User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsEcrRepository",
                        "Id": repoArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"RepositoryName": repoName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF DE.CM-8",
                        "NIST SP 800-53 RA-5",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.6.1",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": repoArn + "/ecr-no-scan",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": repoArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ECR.1] ECR repositories should be configured to scan images on push",
                "Description": "ECR repository "
                + repoName
                + " is configured to scan images on push.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your repository should be configured to scan on push refer to the Image Scanning section in the Amazon ECR User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsEcrRepository",
                        "Id": repoArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"RepositoryName": repoName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.CM-8",
                        "NIST SP 800-53 RA-5",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.6.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding


@registry.register_check("ecr")
def ecr_repo_image_lifecycle_policy_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_repositories(cache)
    myRepos = response["repositories"]
    for repo in myRepos:
        repoArn = str(repo["repositoryArn"])
        repoName = str(repo["repositoryName"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            # this is a passing finding
            response = ecr.get_lifecycle_policy(repositoryName=repoName)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": repoArn + "/ecr-lifecycle-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": repoArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ECR.2] ECR repositories should be have an image lifecycle policy configured",
                "Description": "ECR repository "
                + repoName
                + " does not have an image lifecycle policy configured. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your repository should be configured to have an image lifecycle policy refer to the Amazon ECR Lifecycle Policies section in the Amazon ECR User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsEcrRepository",
                        "Id": repoArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"RepositoryName": repoName}},
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
        except:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": repoArn + "/ecr-lifecycle-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": repoArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[ECR.2] ECR repositories should be have an image lifecycle policy configured",
                "Description": "ECR repository "
                + repoName
                + " does not have an image lifecycle policy configured. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your repository should be configured to have an image lifecycle policy refer to the Amazon ECR Lifecycle Policies section in the Amazon ECR User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsEcrRepository",
                        "Id": repoArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"RepositoryName": repoName}},
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


@registry.register_check("ecr")
def ecr_repo_permission_policy(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_repositories(cache)
    myRepos = response["repositories"]
    for repo in myRepos:
        repoArn = str(repo["repositoryArn"])
        repoName = str(repo["repositoryName"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            # this is a passing finding
            response = ecr.get_repository_policy(repositoryName=repoName)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": repoArn + "/ecr-repo-access-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": repoArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ECR.3] ECR repositories should be have a repository policy configured",
                "Description": "ECR repository "
                + repoName
                + " has a repository policy configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your repository should be configured to have a repository policy refer to the Amazon ECR Repository Policies section in the Amazon ECR User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsEcrRepository",
                        "Id": repoArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"RepositoryName": repoName}},
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
                "Id": repoArn + "/ecr-repo-access-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": repoArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[ECR.3] ECR repositories should be have a repository policy configured",
                "Description": "ECR repository "
                + repoName
                + " does not have a repository policy configured. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your repository should be configured to have a repository policy refer to the Amazon ECR Repository Policies section in the Amazon ECR User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html",
                    }
                },
                "ProductFields": {"Product Name": "Day2SecurityBot"},
                "Resources": [
                    {
                        "Type": "AwsEcrRepository",
                        "Id": repoArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"RepositoryName": repoName}},
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


@registry.register_check("ecr")
def ecr_latest_image_vuln_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_repositories(cache)
    myRepos = response["repositories"]
    for repo in myRepos:
        repoArn = str(repo["repositoryArn"])
        repoName = str(repo["repositoryName"])
        scanningConfig = str(repo["imageScanningConfiguration"]["scanOnPush"])
        if scanningConfig == "True":
            try:
                response = ecr.describe_images(
                    repositoryName=repoName, filter={"tagStatus": "TAGGED"}, maxResults=1000,
                )
                for images in response["imageDetails"]:
                    imageDigest = str(images["imageDigest"])
                    # use the first tag only as we need it to create the canonical ID for the Resource.Id in the ASFF for the Container Resource.Type
                    imageTag = str(images["imageTags"][0])
                    imageVulnCheck = str(
                        images["imageScanFindingsSummary"]["findingSeverityCounts"]
                    )
                    # ISO Time
                    iso8601Time = (
                        datetime.datetime.utcnow()
                        .replace(tzinfo=datetime.timezone.utc)
                        .isoformat()
                    )
                    if imageVulnCheck != "{}":
                        vulnDeepLink = (
                            "https://console.aws.amazon.com/ecr/repositories/"
                            + repoName
                            + "/image/"
                            + imageDigest
                            + "/scan-results?region="
                            + awsRegion
                        )
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": repoName + "/" + imageDigest + "/ecr-latest-image-vuln-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": imageDigest,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/Vulnerabilities/CVE",
                                "Software and Configuration Checks/AWS Security Best Practices",
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "MEDIUM"},
                            "Confidence": 99,
                            "Title": "[ECR.4] The latest image in an ECR Repository should not have any vulnerabilities",
                            "Description": "The latest image in the ECR repository "
                            + repoName
                            + " has the following vulnerabilities reported: "
                            + imageVulnCheck
                            + ". Refer to the SourceUrl or Remediation.Recommendation.Url to review the specific vulnerabilities and remediation information from ECR.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "Click here to navigate to the ECR Vulnerability console for this image",
                                    "Url": vulnDeepLink,
                                }
                            },
                            "SourceUrl": vulnDeepLink,
                            "ProductFields": {"Product Name": "Day2SecurityBot"},
                            "Resources": [
                                {
                                    "Type": "Container",
                                    "Id": repoName + ":" + imageTag,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Container": {
                                            "Name": repoName + ":" + imageTag,
                                            "ImageId": imageDigest,
                                        },
                                        "Other": {
                                            "RepositoryName": repoName,
                                            "RepositoryArn": repoArn,
                                        },
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF DE.CM-8",
                                    "NIST SP 800-53 RA-5",
                                    "AICPA TSC CC7.1",
                                    "ISO 27001:2013 A.12.6.1",
                                ],
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": repoName + "/" + imageDigest + "/ecr-latest-image-vuln-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": imageDigest,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/Vulnerabilities/CVE",
                                "Software and Configuration Checks/AWS Security Best Practices",
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[ECR.4] The latest image in an ECR Repository should not have any vulnerabilities",
                            "Description": "The latest image in the ECR repository "
                            + repoName
                            + " does not have any vulnerabilities reported.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "Click here to navigate to the ECR Vulnerability console for this image",
                                    "Url": vulnDeepLink,
                                }
                            },
                            "SourceUrl": vulnDeepLink,
                            "ProductFields": {"Product Name": "Day2SecurityBot"},
                            "Resources": [
                                {
                                    "Type": "Container",
                                    "Id": repoName + ":" + imageTag,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Container": {
                                            "Name": repoName + ":" + imageTag,
                                            "ImageId": imageDigest,
                                        },
                                        "Other": {
                                            "RepositoryName": repoName,
                                            "RepositoryArn": repoArn,
                                        },
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF DE.CM-8",
                                    "NIST SP 800-53 RA-5",
                                    "AICPA TSC CC7.1",
                                    "ISO 27001:2013 A.12.6.1",
                                ],
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED",
                        }
                        yield finding
            except Exception as e:
                print(e)
        else:
            pass
