import requests
from datetime import datetime
import json


def send_slack(region, f_id, msg):
    """ Send payload to slack """
    webhook_url = "https://hooks.slack.com/services/TSLACKIPD/BWEBHOOKTOKERN"
    footer_icon = 'https://howtofightnow.com/wp-content/uploads/2018/11/cartoon-firewall-hi.png'
    color = '#E01E5A'
    level = ':boom: ALERT :boom:'
    curr_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    console_url = 'https://console.aws.amazon.com/securityhub'
    fallback = f"finding - {console_url}/home?region={region}#/findings?search=id%3D${f_id}"
    payload = {"username": "SecurityHub",
               "attachments": [{"fallback": fallback,
                                "pretext": level,
                                "color": color,
                                "text": f"AWS SecurityHub finding in {region} {msg}",
                                "footer": f"{curr_time}\n{fallback}",
                                "footer_icon": footer_icon}]}
    requests.post(webhook_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})


def handler(event, context):
    finding_id = event['Finding_ID']
    finding_desc = event['Finding_description']
    region = event['Region']
    severity = event['severity']
    finding_type = event['Finding_Type']
    msg = f"Finding new detection: severity {severity}, type: {finding_type} - {finding_desc}"
    send_slack(region, finding_id, msg)
    return {"Status": "Ok"}

