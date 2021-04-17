import requests
from datetime import datetime
import json


def send_slack(region, messageId):
    """ Send payload to slack """
    webhook_url = "https://hooks.slack.com/services/TSLACKIPD/BWEBHOOKTOKERN"
    footer_icon = 'https://howtofightnow.com/wp-content/uploads/2018/11/cartoon-firewall-hi.png'
    color = '#E01E5A'
    level = ':boom: ALERT :boom:'
    curr_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    message = f"Finding new IP {messageId}"
    console_url = 'https://console.aws.amazon.com/securityhub'
    fallback = f"finding - {console_url}/home?region={region}#/findings?search=id%3D${messageId}"
    payload = {"username": "SecurityHub",
               "attachments": [{"fallback": fallback,
                                "pretext": level,
                                "color": color,
                                "text": f"AWS SecurityHub finding in {region} {message}",
                                "footer": f"{curr_time}\n{fallback}",
                                "footer_icon": footer_icon}]}
    requests.post(webhook_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})


def handler(event, context):
    message_id = event['HostIp']
    region = event['Region']
    send_slack(region, message_id)
    return {"Status": "Ok"}

