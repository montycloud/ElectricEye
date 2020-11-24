import os
import boto3
import json
import urllib3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    # create ssm client
    ssm = boto3.client('ssm')
    # create env var for SSM Parameter containing the Microsoft Teams webhook
    webhookParam = os.environ['MS_TEAMS_WEBHOOK_PARAMETER']
    http = urllib3.PoolManager()
    # retrieve Teams webhook from SSM
    try:
        response = ssm.get_parameter(Name=webhookParam, WithDecryption=True)
        response_object = str(response['Parameter']['Value'])
        response_object_dict = json.loads(response_object)
        teams_hooks = response_object_dict.get('teams_hooks')
    except Exception as e:
        print(e)
    teamsHeaders = {'Content-Type': 'application/json'}
    for findings in event['detail']['findings']:
        severityLabel = str(findings['Severity']['Label'])
        electricEyeCheck = str(findings['Title'])
        awsAccountId = str(findings['AwsAccountId'])
        for resources in findings['Resources']:
            resourceId = str(resources['Id'])
            teamsMessage = 'A new ' + severityLabel + ' severity finding for ' + resourceId + ' in acccount ' + awsAccountId + ' has been created in Security Hub due to failing the check: ' + electricEyeCheck
            message = {'text': teamsMessage}
            for webhook in teams_hooks:
                status = http.request('POST', webhook, headers=teamsHeaders, body=json.dumps(message).encode('utf-8'))
                logging.info(status)