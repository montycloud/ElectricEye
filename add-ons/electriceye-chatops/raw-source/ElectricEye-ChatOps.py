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
    # create env var for SSM Parameter containing Slack Webhook URL
    notification_parameters = os.environ['NOTIFICATION_PARAMETER']
    http = urllib3.PoolManager()
    # retrieve slack webhook from SSM
    slack_hooks = []
    teams_hooks = []
    try:
        response = ssm.get_parameter(Name=notification_parameters, WithDecryption=True)
        response_object = str(response['Parameter']['Value'])
        response_object_dict = json.loads(response_object)
        slack_hooks = response_object_dict.get('slack_hooks')
        teams_hooks = response_object_dict.get('teams_hooks')
    except Exception as e:
          logger.exception(e)

    notification_headers = {'Content-Type': 'application/json'}
    color_progression = {
        'LOW': '#FFBF00',
        'MEDIUM': '#F39C12',
        'HIGH': '#E74C3C',
        'CRITICAL': '#A93226'
    }
    for findings in event['detail']['findings']:
        severityLabel = str(findings['Severity']['Label'])
        severityColor = color_progression.get(severityLabel,"#CACFD2")
        electricEyeCheck = str(findings['Title'])
        awsAccountId = str('*')+str(findings['AwsAccountId'])+str('*')
        for resources in findings['Resources']:
            resourceId = str('*')+str(resources['Id'])+str('*')
            Message = 'A new ' + severityLabel + ' severity finding for ' + resourceId + ' in account ' + awsAccountId + ' has been found failing the check: ' +electricEyeCheck
            slack_payload = {
                "username": "DRBOT",
                "text": "DAY2™ SecurityBot",
                "type": "plain_text",
                "attachments": [
                    {
                        "color": severityColor,
                        "text": Message,
                    }
                ]
            }
            teams_payload = {
                "title": "DAY2™ SecurityBot",
                "type": "plain_text",
                 "text": Message,
                "themeColor": severityColor
            }

            for webhook in slack_hooks:
                status = http.request('POST', webhook, headers=notification_headers, body=json.dumps(slack_payload).encode('utf-8'))
                logger.info(status)
            for channel in teams_hooks:
                status = http.request('POST', channel, headers=notification_headers, body=json.dumps(teams_payload).encode('utf-8'))
                logger.info(status)