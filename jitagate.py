#!/usr/bin/env python

import boto3
import botocore
import json
import os
import requests

# Get the approvers for the given tailscale group
#   ddb_approvers_table:    the name of the approvers table
#   ts_group:               the tailscale group to get the approvers for (partition key for DynamoDB table)
def get_approvers(ddb_approvers_table, ts_group):
    client = boto3.client('dynamodb')
    try:
        res = client.get_item(Key = {'ts_group': {'S': ts_group}}, TableName = ddb_approvers_table)
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
        res = client.scan(TableName = ddb_approvers_table, ProjectionExpression = 'ts_group')
    except botocore.exceptions.ClientError as e:
        ##### Better error handling here #####
        raise Exception(e)
    else:
        groups = []
        for item in res['Items']:
            groups.append(item['ts_group']['S'])
        return groups

# Generate the modal to present the user in slack
#   trigger_id: the trigger_id generated when the user issued the slash command (3 second lifespan)
#   groups:     the list of tailscale groups to present to the user
def get_request_modal(trigger_id, groups):
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
                            'text': 'Group list',
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
                                    'text': '*30 min*',
                                    'emoji': True
                                },
                                'value': '1800'
                            },
                            {
                                'text': {
                                    'type': 'plain_text',
                                    'text': '*1 hour*',
                                    'emoji': True
                                },
                                'value': '3600'
                            },
                            {
                                'text': {
                                    'type': 'plain_text',
                                    'text': '*6 hours*',
                                    'emoji': True
                                },
                                'value': '21600'
                            },
                            {
                                'text': {
                                    'type': 'plain_text',
                                    'text': '*12 hours*',
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
                        'text': '*{}*'.format(group),
                        'emoji': True
                    },
                    'value': group
                 }
        view['blocks'][2]['accessory']['options'].append(option)
    return {'trigger_id': trigger_id, 'view': view}

# Get the secret string from secrets manager
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
    ts_secret_name = os.environ.get('TAILSCALE_SECRET_NAME', 'jitagate/tailscale_oauth')
    tailnet = os.environ.get('TAILNET_NAME', '-')
    ddb_approvers_table = os.environ.get('DYNAMODB_TABLE_NAME', 'jitagate_approvers')

    secret_string = get_secret(slack_secret_name)
    slack_webhook = secret_string['webhook']
    secret_string = get_secret(ts_secret_name)
    ts_api_token = get_tailscale_api_token(secret_string)['access_token']
#    policy = tailscale_api_get(ts_api_token, tailnet, 'acl')
#    ts_users = tailscale_api_get(ts_api_token, tailnet, 'users')
#    approvers = get_approvers(ddb_approvers_table, 'testers')
    groups = get_groups(ddb_approvers_table)
    modal = get_request_modal('my_trigger_id', groups)
    print(groups)
    print(json.dumps(modal))

if __name__ == '__main__':
    main()
