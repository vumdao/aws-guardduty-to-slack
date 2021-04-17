#!/usr/bin/env python3

from aws_cdk import core
from guard_duty.guard_duty_stack import StepFunctionMachine


app = core.App()
core_env = core.Environment(region='eu-west-2')
StepFunctionMachine(app, "guard-duty", env=core_env)

app.synth()
