<p align="center">
  <a href="https://dev.to/vumdao">
    <img alt="AWS GuardDuty Combine With Security Hub And Slack" src="https://github.com/vumdao/aws-guardduty-to-slack/blob/master/cover.png?raw=true" width="700" />
  </a>
</p>
<h1 align="center">
  <div><b>AWS GuardDuty Combine With Security Hub And Slack</b></div>
</h1>

### - **This post bases on the blog [Automatically block suspicious traffic with AWS Network Firewall and Amazon GuardDuty](https://aws.amazon.com/blogs/security/automatically-block-suspicious-traffic-with-aws-network-firewall-and-amazon-guardduty) but also send all MEDIUM and HIGH findings to slack**

### - **Build completely this infrastructure using AWS CDK**

---

## What’s In This Document
- [Write Lambda function to block an IP address, update dynamodb table and network firewall then notify to slack](#-Write-Lambda-function-to-block-an-IP-address,-update-dynamodb-table-and-network-firewall-then-notify-to-slack)
- [Write Lambda function to notify finding from Security hub](#-Write-Lambda-function-to-notify-finding-from-Security-hub)
- [Create Network Firewall rule groups](#-Create-Network-Firewall-rule-groups)
- [Step function and state machine for catching IPv4](#-Step-function-and-state-machine-for-catching-IPv4)
- [Cloudwatch Event Rule for Security Hub - GuardDuty findings with remote IP](#-Cloudwatch-Event-Rule-for-Security-Hub---GuardDuty-findings-with-remote-IP)
- [Step function and state machine for finding others](#-Step-function-and-state-machine-for-finding-others)
- [Cloudwatch Event Rule for Security Hub - GuardDuty findings others](#-Cloudwatch-Event-Rule-for-Security-Hub---GuardDuty-findings-others)
- [Test by execute step function with sample finding](#-Test-by-execute-step-function-with-sample-finding)

---

### 🚀 **[Write Lambda function to block an IP address](#-Write-Lambda-function-to-block-an-IP-address)**
- There are two lambda functon here both handle input from cloudwatch event where catching the IPv4

    - Update the IPv4 to dynamodb for keep track and/or prune the IP later
```
import json
import os
import boto3
import dateutil.parser


ACLMETATABLE = os.environ['ACLMETATABLE']
ddb = boto3.resource('dynamodb')
table = ddb.Table(ACLMETATABLE)


def convert_to_epoch(timestamp):
    parsed_t = dateutil.parser.parse(timestamp)
    t_in_seconds = parsed_t.strftime('%s')
    print(t_in_seconds)
    return t_in_seconds


def create_ddb_rule(record):
    response = table.put_item(
        Item=record,
        ReturnValues='ALL_OLD'
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        if 'Attributes' in response:
            print("updated existing record, no new IP")
            return False
        else:
            print("log -- successfully added DDB state entry %s" % (record))
            return True
    else:
        print("log -- error adding DDB state entry for %s" % (record))
        print(response)
        raise


def getAllIPs():
    IPList = []
    try:
        response = table.scan()
        if response['Items']:
            print("log -- found records")
            for item in response['Items']:
                print("HostIp %s" %item['HostIp'])
                IPList.append({"IP": item['HostIp']})
        else:
            print("log -- no entries found.")
    except Exception as e:
        print('something went wrong')
        raise
    return IPList


def handler(event, context):
    print("log -- Event: %s " % json.dumps(event))
    epoch_time = convert_to_epoch(str(event['Timestamp']))
    record = {
        'HostIp': str(event['HostIp']),
        'Timestamp': str(event['Timestamp']),
        'CreatedAt': int(epoch_time),
        'FindingId': str(event['FindingId']),
        'AccountId': str(event['AccountId']),
        'Region': str(event['Region'])
        }
    result = create_ddb_rule(record)
    if result:
        record['IPList'] = getAllIPs()
        record['NewIP'] = True
    else:
        record['NewIP'] = False
    return record
```

 - Update network firewall

```
import os
import json
import boto3


RuleGroupArn = os.environ['FIREWALLRULEGROUP']
RuleGroupPriority = os.environ['RULEGROUPPRI']
CustomActionName = os.environ['CUSTOMACTIONNAME']
CustomActionValue = os.environ['CUSTOMACTIONVALUE']

client = boto3.client('network-firewall')


def create_sources(block_list):
    response = list()
    for i in block_list:
        response.append({'AddressDefinition': str(i['IP']) + '/32'})
    return response


def get_rg_config():
    response = client.describe_rule_group(
        RuleGroupArn=RuleGroupArn,
        Type='STATELESS'
    )
    return response


def update_rg_config(block_list):
    cur_rg_config = get_rg_config()
    rg_priority_dst = int(RuleGroupPriority) + 100

    """ Create new rule from dictionary of IPs CIDRS to block """
    new_rules = [
        {
            'RuleDefinition': {
                'MatchAttributes': {
                    'Sources': create_sources(block_list)
                },
                'Actions': [
                    'aws:drop',
                    CustomActionName
                ]
            },
            'Priority': int(RuleGroupPriority)
        },
        {
            'RuleDefinition': {
                'MatchAttributes': {
                    'Destinations': create_sources(block_list)
                },
                'Actions': [
                    'aws:drop',
                    CustomActionName
                ]
            },
            'Priority': int(rg_priority_dst)
        }
    ]
    # Custom Actions provide CloudWatch metrics
    custom_actions = [
        {
            'ActionName': CustomActionName,
            'ActionDefinition': {
                'PublishMetricAction': {
                    'Dimensions': [
                        {
                            'Value': CustomActionValue
                        }
                    ]
                }
            }
        }
    ]
    # Preserve current rules not used here in rule group by appending to new rule
    new_rg_config = cur_rg_config['RuleGroup']['RulesSource']['StatelessRulesAndCustomActions']['StatelessRules']
    try:
        for r in new_rg_config:
            if int(r['Priority']) not in [int(RuleGroupPriority), int(rg_priority_dst)]:
                new_rules.append(r)

        """ Update the rule group """
        print(f"Update Rule Group ARN, {RuleGroupArn}.")
        response = client.update_rule_group(
            UpdateToken=cur_rg_config['UpdateToken'],
            RuleGroupArn=RuleGroupArn,
            RuleGroup={
                'RulesSource': {
                    'StatelessRulesAndCustomActions': {
                        'StatelessRules':
                            new_rules,
                        'CustomActions':
                            custom_actions
                    }
                }
            },
            Type='STATELESS',
            Description='GD2NFW Blog Sample',
            DryRun=False
        )
    except Exception as e:
        print('something went wrong')
        raise


def handler(event, context):
    print("log -- Event: %s " % json.dumps(event))
    # Retrieve a list of IPs delivered from the previous step in the State Machine
    block_list = event['IPList']
    # If empty, provide a fake entry - rule group update requires at least one entry
    if len(block_list) == 0:
        block_list = [{'IP': '127.0.0.1'}]
    # update the AWS Network Firewall Rule Group
    # replace with the updated list of IPs
    update_rg_config(block_list)
    #
    # check if the function was called for blocking or pruning
    if 'HostIp' in event:
        # blocking completed, pass the data on to the next step
        record = {
            'HostIp': str(event['HostIp']),
            'Timestamp': str(event['Timestamp']),
            'FindingId': str(event['FindingId']),
            'AccountId': str(event['AccountId']),
            'Region': str(event['Region']),
            'Result': True
        }
        return record
    else:
        # this was a pruning action
        return {
          "PruningSuccessful": True
        }
```

- Notify block IP to slack
```
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
```

### 🚀 **[Write Lambda function to notify finding from Security hub](#-Write-Lambda-function-to-notify-finding-from-Security-hub)**

```
import requests
from datetime import datetime
import json


def send_slack(region, f_id, msg):
    """ Send payload to slack """
    webhook_url = "https://hooks.slack.com/services/TSLACKID/BSLACKWEBHOOKTOKEN"
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
```

### 🚀 **[Create Network Firewall rule groups](#-Create-Network-Firewall-rule-groups)**
- This is the new service and only applied to some regions
```
        rg_property = network_fw.CfnRuleGroup.RuleGroupProperty(
            rule_variables=None,
            rules_source=network_fw.CfnRuleGroup.RulesSourceProperty(
                stateless_rules_and_custom_actions=network_fw.CfnRuleGroup.StatelessRulesAndCustomActionsProperty(
                    stateless_rules=[
                        network_fw.CfnRuleGroup.StatelessRuleProperty(
                            priority=10,
                            rule_definition=network_fw.CfnRuleGroup.RuleDefinitionProperty(
                                actions=["aws:drop"],
                                match_attributes=network_fw.CfnRuleGroup.MatchAttributesProperty(
                                    destinations=[
                                        network_fw.CfnRuleGroup.AddressProperty(
                                            address_definition="127.0.0.1/32"
                                        )
                                    ]
                                )
                            )
                        )
                    ]
                )
            )
        )

        nf_rule_group = network_fw.CfnRuleGroup(
            scope=self, id='GuardDutyNetworkFireWallRuleGroup',
            capacity=100,
            rule_group_name='guardduty-network-firewall',
            type='STATELESS',
            description='Guard Duty network firewall rule group',
            tags=[core.CfnTag(key='Name', value='cfn.rule-group.stack')],
            rule_group=rg_property
        )
```

![Alt-Text](https://github.com/vumdao/aws-guardduty-to-slack/blob/master/networkFirewallRuleGroup.png?raw=true)

### 🚀 **[Step function and state machine for catching IPv4](#-Step-function-and-state-machine-for-catching-IPv4)**
![Alt-Text](https://github.com/vumdao/aws-guardduty-to-slack/blob/master/stepfunctions_guardDuty.png?raw=true)

### 🚀 **[Cloudwatch Event Rule for Security Hub - GuardDuty findings with remote IP](#-Cloudwatch-Event-Rule-for-Security-Hub---GuardDuty-findings-with-remote-IP)**
```
{
  "detail-type": [
    "GuardDuty Finding"
  ],
  "detail": {
    "findings": {
      "ProductFields": {
        "aws/guardduty/service/action/networkConnectionAction/remoteIpDetails/ipAddressV4": [
          {
            "exists": true
          }
        ]
      }
    }
  },
  "source": [
    "aws.securityhub"
  ],
  "account": [
    "123456789012"
  ]
}
```

### 🚀 **[Step function and state machine for finding others](#-Step-function-and-state-machine-for-finding-others)**
![Alt-Text](https://github.com/vumdao/aws-guardduty-to-slack/blob/master/stepfunctions_sechub.png?raw=true)

### 🚀 **[Cloudwatch Event Rule for Security Hub - GuardDuty findings others](#-Cloudwatch-Event-Rule-for-Security-Hub---GuardDuty-findings-others)**
```
{
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "severity": [
      5,
      8
    ]
  },
  "source": [
    "aws.securityhub"
  ],
  "account": [
    "661798210997"
  ]
}
```

### 🚀 **[Test by execute step function with sample finding](#-Test-by-execute-step-function-with-sample-finding)**
- Start execution of step function using [Finding Sample](https://raw.githubusercontent.com/aws-samples/aws-networkfirewall-guardduty/main/tests/securityhub-testevent.json)

- Test

![Alt-test](https://github.com/vumdao/aws-guardduty-to-slack/blob/master/test_slack.png?raw=true)

---

<h3 align="center">
  <a href="https://dev.to/vumdao">:stars: Blog</a>
  <span> · </span>
  <a href="https://github.com/vumdao/">Github</a>
  <span> · </span>
  <a href="https://stackoverflow.com/users/11430272/vumdao">Web</a>
  <span> · </span>
  <a href="https://www.linkedin.com/in/vu-dao-9280ab43/">Linkedin</a>
  <span> · </span>
  <a href="https://www.linkedin.com/groups/12488649/">Group</a>
  <span> · </span>
  <a href="https://www.facebook.com/CloudOpz-104917804863956">Page</a>
  <span> · </span>
  <a href="https://twitter.com/VuDao81124667">Twitter :stars:</a>
</h3>

