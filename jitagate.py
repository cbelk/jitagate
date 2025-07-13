#!/usr/bin/env python

import boto3
import botocore
import json
import os
import requests

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
def get_tailscale_api_token(oauth_client):
    url = 'https://api.tailscale.com/api/v2/oauth/token'
    data = {
            'client_id': oauth_client['client_id'],
            'client_secret': oauth_client['client_secret'],
            }
    res = requests.post(url, data=data)
    return res.json()

# Send message to Slack webhook
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
    policy = tailscale_api_get(ts_api_token, tailnet, 'acl')
    ts_users = tailscale_api_get(ts_api_token, tailnet, 'users')
    approvers = get_approvers(ddb_approvers_table, 'testers')
    print(policy)
    print(ts_users)
    print(approvers)

if __name__ == '__main__':
    main()
