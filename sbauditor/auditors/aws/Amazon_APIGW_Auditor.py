import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
apigateway = boto3.client("apigateway")


def get_rest_apis(cache):
    response = cache.get("get_rest_apis")
    if response:
        return response
    cache["get_rest_apis"] = apigateway.get_rest_apis(limit=500)
    return cache["get_rest_apis"]


@registry.register_check("apigateway")
def api_gateway_stage_metrics_enabled_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for restapi in get_rest_apis(cache)["items"]:
        apiGwApiId = str(restapi["id"])
        apiGwApiName = str(restapi["name"])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response["item"]:
            apiStageName = str(apistages["stageName"])
            apiStageDeploymentId = str(apistages["deploymentId"])
            apiStageArn = f"arn:{awsPartition}:apigateway:{awsRegion}::/restapis/{apiGwApiId}/stages/{apiStageName}"
            # is is possible methodSettings is empty indicating metrics are not enabled
            try:
                metricsCheck = str(apistages["methodSettings"]["*/*"]["metricsEnabled"])
            except KeyError:
                metricsCheck = "False"
            if metricsCheck == "False":
                try:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": apiStageArn + "/apigateway-stage-metrics-enabled-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": apiStageArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[APIGateway.1] API Gateway Rest API Stages should have CloudWatch Metrics enabled",
                        "Description": "API Gateway stage "
                        + apiStageName
                        + " for Rest API "
                        + apiGwApiName
                        + " does not have CloudWatch metrics enabled. You can monitor API execution by using CloudWatch, which collects and processes raw data from API Gateway into readable, near-real-time metrics. These statistics are recorded for a period of 15 months so you can access historical information and gain a better perspective on how your web application or service is performing. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your API Gateway stage should have CloudWatch Metrics enabled refer to the Monitor API Execution with Amazon CloudWatch section of the Amazon API Gateway Developer Guide",
                                "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/monitoring-cloudwatch.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsApiGatewayRestApi",
                                "Id": apiStageArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "deploymentId": apiStageDeploymentId,
                                        "stageName": apiStageName,
                                    }
                                },
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
                except Exception as e:
                    print(e)
            else:
                try:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": apiStageArn + "/apigateway-stage-metrics-enabled-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": apiStageArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[APIGateway.1] API Gateway Rest API Stages should have CloudWatch Metrics enabled",
                        "Description": "API Gateway stage "
                        + apiStageName
                        + " for Rest API "
                        + apiGwApiName
                        + " has CloudWatch metrics enabled.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your API Gateway stage should have CloudWatch Metrics enabled refer to the Monitor API Execution with Amazon CloudWatch section of the Amazon API Gateway Developer Guide",
                                "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/monitoring-cloudwatch.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsApiGatewayRestApi",
                                "Id": apiStageArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "deploymentId": apiStageDeploymentId,
                                        "stageName": apiStageName,
                                    }
                                },
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
                except Exception as e:
                    print(e)


@registry.register_check("apigateway")
def api_gateway_stage_logging_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for restapi in get_rest_apis(cache)["items"]:
        apiGwApiId = str(restapi["id"])
        apiGwApiName = str(restapi["name"])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response["item"]:
            apiStageName = str(apistages["stageName"])
            apiStageDeploymentId = str(apistages["deploymentId"])
            apiStageArn = f"arn:{awsPartition}:apigateway:{awsRegion}::/restapis/{apiGwApiId}/stages/{apiStageName}"
            # it is possible for methodSettings to be empty indicating logging is Off
            try:
                loggingCheck = str(apistages["methodSettings"]["*/*"]["loggingLevel"])
            except KeyError:
                loggingCheck = "OFF"
            if loggingCheck == "OFF":
                try:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": apiStageArn + "/apigateway-stage-api-logging-enabled-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": apiStageArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[APIGateway.2] API Gateway Rest API Stages should have CloudWatch API Logging enabled",
                        "Description": "API Gateway stage "
                        + apiStageName
                        + " for Rest API "
                        + apiGwApiName
                        + " does not have CloudWatch API Logging enabled. To help debug issues related to request execution or client access to your API, you can enable Amazon CloudWatch Logs to log API calls. The logged data includes errors or execution traces (such as request or response parameter values or payloads), data used by Lambda authorizers (formerly known as custom authorizers), whether API keys are required, whether usage plans are enabled, and so on. Refer to the remediation instructions if this configuration is not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your API Gateway stage should have CloudWatch API Logging enabled refer to the Set Up CloudWatch API Logging in API Gateway section of the Amazon API Gateway Developer Guide",
                                "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsApiGatewayRestApi",
                                "Id": apiStageArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "deploymentId": apiStageDeploymentId,
                                        "stageName": apiStageName,
                                    }
                                },
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
                except Exception as e:
                    print(e)
            else:
                try:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": apiStageArn + "/apigateway-stage-api-logging-enabled-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": apiStageArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[APIGateway.2] API Gateway Rest API Stages should have CloudWatch API Logging enabled",
                        "Description": "API Gateway stage "
                        + apiStageName
                        + " for Rest API "
                        + apiGwApiName
                        + " has CloudWatch API Logging enabled.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your API Gateway stage should have CloudWatch API Logging enabled refer to the Set Up CloudWatch API Logging in API Gateway section of the Amazon API Gateway Developer Guide",
                                "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsApiGatewayRestApi",
                                "Id": apiStageArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "deploymentId": apiStageDeploymentId,
                                        "stageName": apiStageName,
                                    }
                                },
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
                except Exception as e:
                    print(e)


@registry.register_check("apigateway")
def api_gateway_stage_cacheing_enabled_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for restapi in get_rest_apis(cache)["items"]:
        apiGwApiId = str(restapi["id"])
        apiGwApiName = str(restapi["name"])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response["item"]:
            apiStageName = str(apistages["stageName"])
            apiStageDeploymentId = str(apistages["deploymentId"])
            apiStageArn = f"arn:{awsPartition}:apigateway:{awsRegion}::/restapis/{apiGwApiId}/stages/{apiStageName}"
            # it is possible for methodSettings to be empty which indicated caching is not enabled
            try:
                cachingCheck = str(apistages["methodSettings"]["*/*"]["cachingEnabled"])
            except KeyError:
                cachingCheck = "False"
            if cachingCheck == "False":
                try:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": apiStageArn + "/apigateway-stage-caching-enabled-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": apiStageArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[APIGateway.3] API Gateway Rest API Stages should have Caching enabled",
                        "Description": "API Gateway stage "
                        + apiStageName
                        + " for Rest API "
                        + apiGwApiName
                        + " does not have Caching enabled. You can enable API caching in Amazon API Gateway to cache your endpoints responses. With caching, you can reduce the number of calls made to your endpoint and also improve the latency of requests to your API. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your API Gateway stage should have caching enabled refer to the Enable API Caching to Enhance Responsiveness section of the Amazon API Gateway Developer Guide",
                                "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsApiGatewayRestApi",
                                "Id": apiStageArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "deploymentId": apiStageDeploymentId,
                                        "stageName": apiStageName,
                                    }
                                },
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
                except Exception as e:
                    print(e)
            else:
                try:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": apiStageArn + "/apigateway-stage-caching-enabled-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": apiStageArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[APIGateway.3] API Gateway Rest API Stages should have Caching enabled",
                        "Description": "API Gateway stage "
                        + apiStageName
                        + " for Rest API "
                        + apiGwApiName
                        + " has Caching enabled.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your API Gateway stage should have caching enabled refer to the Enable API Caching to Enhance Responsiveness section of the Amazon API Gateway Developer Guide",
                                "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsApiGatewayRestApi",
                                "Id": apiStageArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "deploymentId": apiStageDeploymentId,
                                        "stageName": apiStageName,
                                    }
                                },
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
                except Exception as e:
                    print(e)


@registry.register_check("apigateway")
def api_gateway_stage_cache_encryption_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for restapi in get_rest_apis(cache)["items"]:
        apiGwApiId = str(restapi["id"])
        apiGwApiName = str(restapi["name"])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response["item"]:
            apiStageName = str(apistages["stageName"])
            apiStageDeploymentId = str(apistages["deploymentId"])
            apiStageArn = f"arn:{awsPartition}:apigateway:{awsRegion}::/restapis/{apiGwApiId}/stages/{apiStageName}"
            try:
                cachingEncryptionCheck = str(
                    apistages["methodSettings"]["*/*"]["cacheDataEncrypted"]
                )
            except KeyError:
                cachingEncryptionCheck = "False"
            if cachingEncryptionCheck == "False":
                try:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": apiStageArn + "/apigateway-stage-cache-encryption-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": apiStageArn,
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
                        "Title": "[APIGateway.4] API Gateway Rest API Stages should have cache encryption enabled",
                        "Description": "API Gateway stage "
                        + apiStageName
                        + " for Rest API "
                        + apiGwApiName
                        + " does not have cache encryption enabled. If you choose to enable caching for a REST API, you can enable cache encryption. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your API Gateway stage should have caching encryption enabled refer to the Override API Gateway Stage-Level Caching for Method Caching section of the Amazon API Gateway Developer Guide",
                                "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html#override-api-gateway-stage-cache-for-method-cache",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsApiGatewayRestApi",
                                "Id": apiStageArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "deploymentId": apiStageDeploymentId,
                                        "stageName": apiStageName,
                                    }
                                },
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
                except Exception as e:
                    print(e)
            else:
                try:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": apiStageArn + "/apigateway-stage-cache-encryption-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": apiStageArn,
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
                        "Title": "[APIGateway.4] API Gateway Rest API Stages should have cache encryption enabled",
                        "Description": "API Gateway stage "
                        + apiStageName
                        + " for Rest API "
                        + apiGwApiName
                        + " has cache encryption enabled.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your API Gateway stage should have caching encryption enabled refer to the Override API Gateway Stage-Level Caching for Method Caching section of the Amazon API Gateway Developer Guide",
                                "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html#override-api-gateway-stage-cache-for-method-cache",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsApiGatewayRestApi",
                                "Id": apiStageArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "deploymentId": apiStageDeploymentId,
                                        "stageName": apiStageName,
                                    }
                                },
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
                except Exception as e:
                    print(e)


@registry.register_check("apigateway")
def api_gateway_stage_xray_tracking_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for restapi in get_rest_apis(cache)["items"]:
        apiGwApiId = str(restapi["id"])
        apiGwApiName = str(restapi["name"])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response["item"]:
            apiStageName = str(apistages["stageName"])
            apiStageDeploymentId = str(apistages["deploymentId"])
            apiStageArn = f"arn:{awsPartition}:apigateway:{awsRegion}::/restapis/{apiGwApiId}/stages/{apiStageName}"
            xrayTracingCheck = str(apistages["tracingEnabled"])
            if xrayTracingCheck == "False":
                try:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": apiStageArn + "/apigateway-stage-xray-tracing-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": apiStageArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[APIGateway.5] API Gateway Rest API Stages should have tracing enabled",
                        "Description": "API Gateway stage "
                        + apiStageName
                        + " for Rest API "
                        + apiGwApiName
                        + " does not have tracing enabled. Because X-Ray gives you an end-to-end view of an entire request, you can analyze latencies in your APIs and their backend services. You can use an X-Ray service map to view the latency of an entire request and that of the downstream services that are integrated with X-Ray. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your API Gateway stage should have tracing enabled refer to the Set Up X-Ray Tracing in API Gateway section of the Amazon API Gateway Developer Guide",
                                "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-set-up-tracing.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsApiGatewayRestApi",
                                "Id": apiStageArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "deploymentId": apiStageDeploymentId,
                                        "stageName": apiStageName,
                                    }
                                },
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
                except Exception as e:
                    print(e)
            else:
                try:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": apiStageArn + "/apigateway-stage-xray-tracing-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": apiStageArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[APIGateway.5] API Gateway Rest API Stages should have tracing enabled",
                        "Description": "API Gateway stage "
                        + apiStageName
                        + " for Rest API "
                        + apiGwApiName
                        + " has tracing enabled.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your API Gateway stage should have tracing enabled refer to the Set Up X-Ray Tracing in API Gateway section of the Amazon API Gateway Developer Guide",
                                "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-set-up-tracing.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsApiGatewayRestApi",
                                "Id": apiStageArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "deploymentId": apiStageDeploymentId,
                                        "stageName": apiStageName,
                                    }
                                },
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
                except Exception as e:
                    print(e)


@registry.register_check("apigateway")
def api_gateway_stage_waf_check_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for restapi in get_rest_apis(cache)["items"]:
        apiGwApiId = str(restapi["id"])
        apiGwApiName = str(restapi["name"])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response["item"]:
            apiStageName = str(apistages["stageName"])
            apiStageDeploymentId = str(apistages["deploymentId"])
            apiStageArn = f"arn:{awsPartition}:apigateway:{awsRegion}::/restapis/{apiGwApiId}/stages/{apiStageName}"
            try:
                wafCheck = str(apistages["webAclArn"])
                # this is a passing check
                try:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": apiStageArn + "/apigateway-stage-waf-protection-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": apiStageArn,
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
                        "Title": "[APIGateway.6] API Gateway Rest API Stages should be protected by an AWS WAF Web ACL",
                        "Description": "API Gateway stage "
                        + apiStageName
                        + " for Rest API "
                        + apiGwApiName
                        + " is protected by an AWS WAF Web ACL.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your API Gateway stage should be protected by WAF refer to the Set Up AWS WAF in API Gateway section of the Amazon API Gateway Developer Guide",
                                "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-setup-waf.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsApiGatewayRestApi",
                                "Id": apiStageArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "deploymentId": apiStageDeploymentId,
                                        "stageName": apiStageName,
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF DE.AE-2",
                                "NIST SP 800-53 AU-6",
                                "NIST SP 800-53 CA-7",
                                "NIST SP 800-53 IR-4",
                                "NIST SP 800-53 SI-4",
                                "AICPA TSC CC7.2",
                                "ISO 27001:2013 A.12.4.1",
                                "ISO 27001:2013 A.16.1.1",
                                "ISO 27001:2013 A.16.1.4",
                            ],
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
                except Exception as e:
                    print(e)
            except Exception as e:
                if str(e) == "'webAclArn'":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": apiStageArn + "/apigateway-stage-waf-protection-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": apiStageArn,
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
                        "Title": "[APIGateway.6] API Gateway Rest API Stages should be protected by an AWS WAF Web ACL",
                        "Description": "API Gateway stage "
                                       + apiStageName
                                       + " for Rest API "
                                       + apiGwApiName
                                       + " is not protected by an AWS WAF Web ACL. You can use AWS WAF to protect your API Gateway API from common web exploits, such as SQL injection and cross-site scripting (XSS) attacks. These could affect API availability and performance, compromise security, or consume excessive resources. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your API Gateway stage should be protected by WAF refer to the Set Up AWS WAF in API Gateway section of the Amazon API Gateway Developer Guide",
                                "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-setup-waf.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsApiGatewayRestApi",
                                "Id": apiStageArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "deploymentId": apiStageDeploymentId,
                                        "stageName": apiStageName,
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF DE.AE-2",
                                "NIST SP 800-53 AU-6",
                                "NIST SP 800-53 CA-7",
                                "NIST SP 800-53 IR-4",
                                "NIST SP 800-53 SI-4",
                                "AICPA TSC CC7.2",
                                "ISO 27001:2013 A.12.4.1",
                                "ISO 27001:2013 A.16.1.1",
                                "ISO 27001:2013 A.16.1.4",
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    try:
                        yield finding
                    except Exception as e:
                        print(e)
                else:
                    print(e)
