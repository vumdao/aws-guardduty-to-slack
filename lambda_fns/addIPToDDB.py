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

