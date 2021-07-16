<p align="center">
  <a href="https://dev.to/vumdao">
    <img alt="AWS GuardDuty Combine With Security Hub And Slack" src="https://github.com/vumdao/aws-guardduty-to-slack/blob/master/cover.png?raw=true" width="700" />
  </a>
</p>
<h1 align="center">
  <div><b>AWS GuardDuty Combine With Security Hub And Slack</b></div>
</h1>

### - **This post bases on the blog [Automatically block suspicious traffic with AWS Network Firewall and Amazon GuardDuty](https://aws.amazon.com/blogs/security/automatically-block-suspicious-traffic-with-aws-network-firewall-and-amazon-guardduty) but also send all MEDIUM and HIGH findings to slack**

### - **Build completely this infrastructure using AWS CDK 2.0**

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
- [Conclusion](#-Conclusion)

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
- This is the new service and only applied to some regions, following is full code of creating completely stack using AWS CDK 2.0 in python3

```
from constructs import Construct
from aws_cdk import (
    Stack, Duration, CfnTag, RemovalPolicy,
    aws_events as event,
    aws_sqs as sqs,
    aws_events_targets as event_target,
    aws_stepfunctions as step_fn,
    aws_stepfunctions_tasks as step_fn_task,
    aws_lambda as _lambda,
    aws_dynamodb as ddb,
    aws_iam as iam,
    aws_networkfirewall as network_fw
)


class StepFunctionMachine(Stack):
    def __init__(self, scope: Construct, construct_id: str, env, **kwargs) -> None:
        super().__init__(scope, construct_id, env=env, **kwargs)

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
            tags=[CfnTag(key='Name', value='cfn.rule-group.stack')],
            rule_group=rg_property
        )

        """ https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html#dlq-considerations """
        dlq_statemachine = sqs.Queue(self, 'DLQStateMachine', queue_name='dlq_state_machine')

        guardduty_firewall_ddb = ddb.Table(
            scope=self, id=f'GuarddutyFirewallDDB',
            table_name='GuardDutyFirewallDDBTable',
            removal_policy=RemovalPolicy.DESTROY,
            partition_key=ddb.Attribute(name='HostIp', type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST
        )

        """ IAM role for ddb permission """
        nf_iam_role = iam.Role(
            self, 'DDBRole', role_name=f'ddb-nf-role-{env.region}',
            assumed_by=iam.ServicePrincipal(service='lambda.amazonaws.com')
        )

        nf_iam_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=["arn:aws:logs:*:*:*"],
                actions=["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
            )
        )

        nf_iam_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[guardduty_firewall_ddb.table_arn, f"{guardduty_firewall_ddb.table_arn}/*"],
                actions=["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Scan"]
            )
        )

        nf_iam_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[nf_rule_group.ref, f"{nf_rule_group.ref}/*"],
                actions=["network-firewall:DescribeRuleGroup", "network-firewall:UpdateRuleGroup"]
            )
        )

        record_ip_in_db = _lambda.Function(
            self, 'RecordIpInDB',
            function_name='record-ip-in-ddb',
            runtime=_lambda.Runtime.PYTHON_3_8,
            code=_lambda.Code.from_asset('lambda_fns'),
            handler='addIPToDDB.handler',
            environment=dict(
                ACLMETATABLE=guardduty_firewall_ddb.table_name
            ),
            role=nf_iam_role
        )

        """
        https://docs.amazonaws.cn/en_us/eventbridge/latest/userguide/eb-event-patterns-content-based-filtering.html
        """
        record_ip_task = step_fn_task.LambdaInvoke(
            self, 'RecordIpDDBTask',
            lambda_function=record_ip_in_db,
            payload=step_fn.TaskInput.from_object(
                {
                    "comment": "Relevant fields from the GuardDuty / Security Hub finding",
                    "HostIp.$": "$.detail.findings[0].ProductFields.aws/guardduty/service/action/networkConnectionAction/remoteIpDetails/ipAddressV4",
                    "Timestamp.$": "$.detail.findings[0].ProductFields.aws/guardduty/service/eventLastSeen",
                    "FindingId.$": "$.id",
                    "AccountId.$": "$.account",
                    "Region.$": "$.region"
                }
            ),
            result_path='$',
            payload_response_only=True
        )

        firewall_update_rule = _lambda.Function(
            scope=self, id='GuardDutyUpdateNetworkFirewallRule',
            function_name='gurdduty-update-networkfirewal-rule-group',
            runtime=_lambda.Runtime.PYTHON_3_8,
            code=_lambda.Code.from_asset('lambda_fns'),
            handler='updateNetworkFireWall.handler',
            environment=dict(
                FIREWALLRULEGROUP=nf_rule_group.ref,
                RULEGROUPPRI='30000',
                CUSTOMACTIONNAME='GuardDutytoFirewall',
                CUSTOMACTIONVALUE='gurdduty-update-networkfirewal-rule-group'
            ),
            role=nf_iam_role
        )

        firewall_update_rule_task = step_fn_task.LambdaInvoke(
            self, 'FirewallUpdateRuleTask',
            lambda_function=firewall_update_rule,
            input_path='$',
            result_path='$',
            payload_response_only=True
        )

        firewall_no_update_job = step_fn.Pass(self, 'No Firewall change')
        notify_failure_job = step_fn.Fail(self, 'NotifyFailureJob', cause='Any Failure', error='Unknown')

        send_to_slack = _lambda.Function(
            scope=self, id='SendAlertToSlack',
            function_name='gurdduty-networkfirewal-to-slack',
            runtime=_lambda.Runtime.PYTHON_3_8,
            handler="sendSMSToSlack.handler",
            code=_lambda.Code.from_asset('lambda_fns')
        )

        send_slack_task = step_fn_task.LambdaInvoke(
            scope=self, id='LambdaToSlackDemo',
            lambda_function=send_to_slack,
            input_path='$',
            result_path='$'
        )

        is_new_ip = step_fn.Choice(self, "New IP?")
        is_block_succeed = step_fn.Choice(self, "Block sucessfully?")

        definition = step_fn.Chain \
            .start(record_ip_task
                   .add_retry(errors=["States.TaskFailed"],
                              interval=Duration.seconds(2),
                              max_attempts=2)
                   .add_catch(errors=["States.ALL"], handler=notify_failure_job)) \
            .next(is_new_ip
                  .when(step_fn.Condition.boolean_equals('$.NewIP', True),
                        firewall_update_rule_task
                            .add_retry(errors=["States.TaskFailed"],
                                       interval=Duration.seconds(2),
                                       max_attempts=2
                                       )
                            .add_catch(errors=["States.ALL"], handler=notify_failure_job)
                            .next(
                                is_block_succeed
                                    .when(step_fn.Condition.boolean_equals('$.Result', False), notify_failure_job)
                                    .otherwise(send_slack_task)
                            )
                        )
                  .otherwise(firewall_no_update_job)
                  )

        guardduty_state_machine = step_fn.StateMachine(
            self, 'GuarddutyStateMachine',
            definition=definition, timeout=Duration.minutes(5), state_machine_name='guardduty-state-machine'
        )

        event.Rule(
            scope=self, id='EventBridgeCatchIPv4',
            description="Security Hub - GuardDuty findings with remote IP",
            rule_name='guardduty-catch-ipv4',
            event_pattern=event.EventPattern(
                account=['123456789012'],
                detail_type=["GuardDuty Finding"],
                source=['aws.securityhub'],
                detail={
                    "findings": {
                        "ProductFields": {
                            "aws/guardduty/service/action/networkConnectionAction/remoteIpDetails/ipAddressV4": [
                                {"exists": True}
                            ]
                        }
                    }
                }
            ),
            targets=[event_target.SfnStateMachine(machine=guardduty_state_machine, dead_letter_queue=dlq_statemachine)]
        )

        """ Send other findings to slack """
        send_finding_to_slack = _lambda.Function(
            self, 'SendFindingToSlack',
            function_name='send-finding-to-slack',
            runtime=_lambda.Runtime.PYTHON_3_8,
            handler="sendFindingToSlack.handler",
            code=_lambda.Code.from_asset('lambda_fns')
        )

        send_findings_task = step_fn_task.LambdaInvoke(
            self, 'SendFindingToSlackTask',
            lambda_function=send_finding_to_slack,
            payload=step_fn.TaskInput.from_object(
                {
                    "comment": "Others fields from the GuardDuty / Security Hub finding",
                    "severity.$": "$.detail.findings[0].Severity.Label",
                    "Account_ID.$": "$.account",
                    "Finding_ID.$": "$.id",
                    "Finding_Type.$": "$.detail.findings[0].Types",
                    "Region.$": "$.region",
                    "Finding_description.$": "$.detail.findings[0].Description"
                }
            ),
            result_path='$'
        )

        slack_failure_job = step_fn.Fail(self, 'SlackNotifyFailureJob', cause='Any Failure', error='Unknown')

        finding_definition = step_fn.Chain \
            .start(send_findings_task
                   .add_retry(errors=["States.TaskFailed"],
                              interval=Duration.seconds(2),
                              max_attempts=2)
                   .add_catch(errors=["States.ALL"], handler=slack_failure_job))

        sechub_findings_state_machine = step_fn.StateMachine(
            self, 'SecHubFindingsStateMachine', definition=finding_definition,
            timeout=Duration.minutes(5), state_machine_name='sechub-finding-state-machine'
        )

        event.Rule(
            scope=self, id='EventBridgeFindings',
            description="Security Hub - GuardDuty findings others",
            rule_name='others-findings',
            event_pattern=event.EventPattern(
                account=['123456789012'],
                source=['aws.securityhub'],
                detail_type=['Security Hub Findings - Imported'],
                detail={"severity": [5, 8]}
            ),
            targets=[event_target.SfnStateMachine(machine=sechub_findings_state_machine,
                                                  dead_letter_queue=dlq_statemachine)]
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
    "123456789012"
  ]
}
```

### 🚀 **[Test by execute step function with sample finding](#-Test-by-execute-step-function-with-sample-finding)**
- Start execution of step function using [Finding Sample](https://raw.githubusercontent.com/aws-samples/aws-networkfirewall-guardduty/main/tests/securityhub-testevent.json)

- Test

![Alt-test](https://github.com/vumdao/aws-guardduty-to-slack/blob/master/test_slack.png?raw=true)

### 🚀 **[Conclusion](#-Conclusion)**
- This is full solution we can apply to product in order to provide high security but consider the price
- TL,DR 

---

<h3 align="center">
  <a href="https://dev.to/vumdao">:stars: Blog</a>
  <span> · </span>
  <a href="https://github.com/vumdao/aws-guardduty-to-slack">Github</a>
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

