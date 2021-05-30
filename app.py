#!/usr/bin/env python3

from aws_cdk import App, Environment
from guard_duty.guard_duty_stack import StepFunctionMachine


app = App()
env = Environment(region='eu-west-2')
StepFunctionMachine(app, "guard-duty", env=env)

app.synth()
