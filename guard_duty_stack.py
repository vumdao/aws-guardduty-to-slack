from aws_cdk import (
    core,
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


class StepFunctionMachine(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, env, **kwargs) -> None:
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
            tags=[core.CfnTag(key='Name', value='cfn.rule-group.stack')],
            rule_group=rg_property
        )

        """ https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html#dlq-considerations """
        dlq_statemachine = sqs.Queue(self, 'DLQStateMachine', queue_name='dlq_state_machine')

        guardduty_firewall_ddb = ddb.Table(
            scope=self, id=f'GuarddutyFirewallDDB',
            table_name='GuardDutyFirewallDDBTable',
            removal_policy=core.RemovalPolicy.DESTROY,
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
                              interval=core.Duration.seconds(2),
                              max_attempts=2)
                   .add_catch(errors=["States.ALL"], handler=notify_failure_job)) \
            .next(is_new_ip
                  .when(step_fn.Condition.boolean_equals('$.NewIP', True),
                        firewall_update_rule_task
                            .add_retry(errors=["States.TaskFailed"],
                                       interval=core.Duration.seconds(2),
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
            definition=definition, timeout=core.Duration.minutes(5), state_machine_name='guardduty-state-machine'
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
                              interval=core.Duration.seconds(2),
                              max_attempts=2)
                   .add_catch(errors=["States.ALL"], handler=slack_failure_job))

        sechub_findings_state_machine = step_fn.StateMachine(
            self, 'SecHubFindingsStateMachine', definition=finding_definition,
            timeout=core.Duration.minutes(5), state_machine_name='sechub-finding-state-machine'
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
