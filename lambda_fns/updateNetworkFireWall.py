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
