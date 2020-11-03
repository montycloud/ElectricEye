import os
import boto3
import json
import urllib3

def lambda_handler(event, context):
    # create ssm client
    ssm = boto3.client('ssm')
    # create env var for SSM Parameter containing Slack Webhook URL
    webhookParam = os.environ['SLACK_WEBHOOK_PARAMETER']
    http = urllib3.PoolManager()
    # retrieve slack webhook from SSM
    try:
        response = ssm.get_parameter(Name=webhookParam,WithDecryption=True)
        slackWebhook = str(response['Parameter']['Value'])
    except Exception as e:
        print(e)
    slackHeaders = {'Content-Type': 'application/json'}
    for findings in event['detail']['findings']:
        severityLabel = str(findings['Severity']['Label'])
        electricEyeCheck = str(findings['Title'])
        awsAccountId = str(findings['AwsAccountId'])
        for resources in findings['Resources']:
            resourceId = str(resources['Id'])
            slackMessage = 'A new ' + severityLabel + ' severity finding for ' + resourceId + ' in acccount ' + awsAccountId + ' has been created in Security Hub due to failing the check: ' + electricEyeCheck
            message = {'text': slackMessage}
            http.request('POST', slackWebhook,  headers=slackHeaders, body=json.dumps(message).encode('utf-8'))