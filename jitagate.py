#!/usr/bin/env python

# Get the slack webhook from secrets manager
def get_slack_webhook():
    client = boto3.client('secretsmanager')
    try:
        secret_response = client.get_secret_value(SecretId='pci_change_detection/slack_webhook')
    except botocore.exceptions.ClientError as e:
        raise Exception(e)
    slack_webhook = json.loads(secret_response['SecretString'])['slack_webhook']
    return slack_webhook

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

def main(event={}, context={}):
    inLambda = os.environ.get('AWS_EXECUTION_ENV') is not None
    if (inLambda):
    else:

if __name__ == '__main__':
    main()
