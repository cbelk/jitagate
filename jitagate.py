#!/usr/bin/env python

import base64
import boto3
import botocore
import json
import os
import requests
from urllib.parse import parse_qs

# Get the approvers for the given tailscale group
#   ddb_approvers_table:    the name of the approvers table
#   ts_group:               the tailscale group to get the approvers for (partition key for DynamoDB table)
def get_approvers(ddb_approvers_table, ts_group):
    client = boto3.client('dynamodb')
    try:
        res = client.get_item(Key={'ts_group': {'S': ts_group}}, TableName=ddb_approvers_table)
    except botocore.exceptions.ClientError as e:
        ##### Better error handling here #####
        raise Exception(e)
    else:
        #return json.loads(res['Item'])
        return res['Item']['approvers']

# Get a list of tailscale groups. This is generated from the partition keys of the approvers table in DynamoDB
#   ddb_approvers_table: the name of the approvers table
def get_groups(ddb_approvers_table):
    client = boto3.client('dynamodb')
    try:
        res = client.scan(TableName=ddb_approvers_table, ProjectionExpression='ts_group')
    except botocore.exceptions.ClientError as e:
        ##### Better error handling here #####
        raise Exception(e)
    else:
        groups = []
        for item in res['Items']:
            groups.append(item['ts_group']['S'])
        return groups

# Generate the loading modal to present the user in slack
#   trigger_id: the trigger_id generated when the user issued the slash command (3 second lifespan)
def get_loading_modal(trigger_id):
    view = {'type': 'modal',
            'close': {
                'type': 'plain_text',
                'text': 'Cancel',
                'emoji': True
            },
            'title': {
                'type': 'plain_text',
                'text': 'Jitagate',
                'emoji': True
            },
            'blocks': [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': '*Loading access request information...*'
                    }
                }
            ]
    }
    return {'trigger_id': trigger_id, 'view': view}

# Generate the modal to replace the loading modal in slack
#   trigger_id: the trigger_id generated when the user issued the slash command (3 second lifespan)
#   groups:     the list of tailscale groups to present to the user
def get_request_modal(view_id, groups):
    view = {'type': 'modal',
            'submit': {
                'type': 'plain_text',
                'text': 'Submit',
                'emoji': True
            },
            'close': {
                'type': 'plain_text',
                'text': 'Cancel',
                'emoji': True
            },
            'title': {
                'type': 'plain_text',
                'text': 'Jitagate',
                'emoji': True
            },
            'blocks': [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': 'Access details:'
                    }
                },
                {
                    'type': 'divider'
                },
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': ':clipboard: *Group*\nChoose which group you need access to'
                    },
                    'accessory': {
                        'type': 'static_select',
                        'placeholder': {
                            'type': 'plain_text',
                            'text': 'group',
                            'emoji': True
                        },
                        'options': []
                    }
                },
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': ':clock1: *Duration*\nHow long do you need access'
                    },
                    'accessory': {
                        'type': 'static_select',
                        'placeholder': {
                            'type': 'plain_text',
                            'text': 'duration',
                            'emoji': True
                        },
                        'options': [
                            {
                                'text': {
                                    'type': 'plain_text',
                                    'text': '30 min',
                                    'emoji': True
                                },
                                'value': '1800'
                            },
                            {
                                'text': {
                                    'type': 'plain_text',
                                    'text': '1 hour',
                                    'emoji': True
                                },
                                'value': '3600'
                            },
                            {
                                'text': {
                                    'type': 'plain_text',
                                    'text': '6 hours',
                                    'emoji': True
                                },
                                'value': '21600'
                            },
                            {
                                'text': {
                                    'type': 'plain_text',
                                    'text': '12 hours',
                                    'emoji': True
                                },
                                'value': '43200'
                            }
                        ],
                        'action_id': 'static_select-action'
                    }
                }
            ]
    }
    for group in groups:
        option = {
                    'text': {
                        'type': 'plain_text',
                        'text': '{}'.format(group),
                        'emoji': True
                    },
                    'value': group
                 }
        view['blocks'][2]['accessory']['options'].append(option)
    return {'view_id': view_id, 'view': view}

# Get the secret string from secrets manager
#   secret_name:  the name of the secret to retrieve from secretsmanager
def get_secret(secret_name):
    client = boto3.client('secretsmanager')
    try:
        secret_response = client.get_secret_value(SecretId=secret_name)
    except botocore.exceptions.ClientError as e:
        ##### Better error handling here #####
        raise Exception(e)
    else:
        return json.loads(secret_response['SecretString'])

# Get an API key from tailscale using the oauth client
#   oauth_client:  the OAuth2 client to use to generate the API token
def get_tailscale_api_token(oauth_client):
    url = 'https://api.tailscale.com/api/v2/oauth/token'
    data = {
            'client_id': oauth_client['client_id'],
            'client_secret': oauth_client['client_secret'],
            }
    res = requests.post(url, data=data)
    return res.json()

# Get information about the slack user with the given user_id
#   token:      the slack oauth token
#   user_id:    the user ID to get info about
def get_slack_user_info(token, user_id):
    url = 'https://slack.com/api/users.info'
    headers = {'Authorization': 'Bearer {}'.format(token)}
    res = requests.get('{}/?user={}'.format(url, user_id), headers=headers)
    return res.json()

# Push the modal view ID to the queue
#   queue:  the SQS queue url
#   view:   the view ID to send to the queue
def push_view_id(queue, view):
    client = boto3.client('sqs')
    try:
        res = client.send_message(QueueUrl=queue, MessageBody=view)
    except botocore.exceptions.ClientError as e:
        ##### Better error handling here #####
        raise Exception(e)
    else:
        return

# Send message to Slack webhook
#   slack_webhook:  the slack webhook to send the message to
#   message:        the message to send
def send_slack_message(slack_webhook, message):
    res = requests.post(slack_webhook, data=json.dumps(message))
    attempts = 1
    while res.status_code >= 500 and attempts < 3:
        res = requests.post(slack_webhook, data=json.dumps(message))
        attempts += 1
    if res.status_code != 200:
        print('[jitagate] Response code: {} Response text: {}'.format(res.status_code, res.text))
    return

# Send response modal to Slack
#   token:  the slack oauth token
#   modal:  the modal to send
def send_slack_modal(url, token, modal):
    headers = {'Content-type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    res = requests.post(url, data=json.dumps(modal), headers=headers)
    return res

# Get a json object from the tailscale API
#   ts_api_token:   the tailscale API token to use
#   tailnet:        the tailnet name to use
#   endpoint:       the API endpoint to retrieve from
def tailscale_api_get(ts_api_token, tailnet, endpoint):
    url = 'https://api.tailscale.com/api/v2/tailnet/{}/{}'.format(tailnet, endpoint)
    headers={"Authorization": 'Bearer {}'.format(ts_api_token), 'Accept': 'application/json'}
    res = requests.get(url, headers=headers)
    attempts = 1
    while res.status_code >= 500 and attempts < 3:
        res = requests.get(url, headers=headers)
        attempts += 1
    if res.status_code != 200:
        print('[jitagate] Response code: {} Response text: {}'.format(res.status_code, res.text))
    return res.json()

def main(event={}, context={}):
    # Variables with defaults that can be overridden with environment variables
    slack_secret_name = os.environ.get('SLACK_SECRET_NAME', 'jitagate/slack_webhook')
    slack_oauth_secret_name = os.environ.get('SLACK_OAUTH_SECRET_NAME', 'jitagate/slack_oauth')
    ts_secret_name = os.environ.get('TAILSCALE_SECRET_NAME', 'jitagate/tailscale_oauth')
    tailnet = os.environ.get('TAILNET_NAME', '-')
    ddb_approvers_table = os.environ.get('DYNAMODB_TABLE_NAME', 'jitagate_approvers')

    # This variable has no default so it has to be set in the environment
    if 'JITAGATE_SQS_URL' not in os.environ:
        exit('[jitagate] JITAGATE_SQS_URL environment variable required')
    sqs_url = os.environ.get('JITAGATE_SQS_URL')

    secret_string = get_secret(slack_oauth_secret_name)
    slack_oauth = secret_string['token']

    if 'Records' in event and event['Records'][0]['eventSource'] == 'aws:sqs':
        view_id = event['Records'][0]['body']
        groups = get_groups(ddb_approvers_table)
        modal = get_request_modal(view_id, groups)
        url = 'https://slack.com/api/views.update'
        res = send_slack_modal(url, slack_oauth, modal)
        print(res.text)
        return

    if event['rawPath'] == '/modal':
        body = parse_qs(base64.b64decode(event['body']).decode('utf-8'))
        modal = get_loading_modal(body['trigger_id'][0])
        url = 'https://slack.com/api/views.open'
        res = send_slack_modal(url, slack_oauth, modal)
        print(res.text)
        view_id = res.json()['view']['id']
        push_view_id(sqs_url, view_id)
        return 'jitagate access request'

    if event['rawPath'] == '/request':
        body = parse_qs(base64.b64decode(event['body']).decode('utf-8'))
        payload = json.loads(body['payload'][0])
        if payload['type'] == 'block_actions':
            return
        elif payload['type'] == 'view_submission':
            group_block_id = payload['view']['blocks'][2]['block_id']
            group_action_id = payload['view']['blocks'][2]['accessory']['action_id']
            duration_block_id = payload['view']['blocks'][3]['block_id']
            group = payload['view']['state']['values'][group_block_id][group_action_id]['selected_option']['value']
            duration = payload['view']['state']['values'][duration_block_id]['static_select-action']['selected_option']['value']
            user_info = get_slack_user_info(slack_oauth, payload['user']['id'])
            print(user_info)
            print('group: {}\nduration: {}'.format(group, duration))
            return

    secret_string = get_secret(slack_secret_name)
    slack_webhook = secret_string['webhook']
    secret_string = get_secret(ts_secret_name)
    ts_api_token = get_tailscale_api_token(secret_string)['access_token']

#    policy = tailscale_api_get(ts_api_token, tailnet, 'acl')
#    ts_users = tailscale_api_get(ts_api_token, tailnet, 'users')
#    approvers = get_approvers(ddb_approvers_table, 'testers')

if __name__ == '__main__':
    main()
