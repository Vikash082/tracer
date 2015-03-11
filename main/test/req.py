import urllib3
import json

http = urllib3.PoolManager()
headers = {'content-type': 'application/json'}

payload = {'src_port': 'b98a1d3a-ac86-4f55-ba00-339c601e4080',
           'dst_port': '98b056d4-c79d-443e-9da9-8bfab60a79a7',
           'policy_id': '37000dea-7d0c-4e18-a7ab-30b99e243adb',
           'action_id': 'ffd51fca-f644-4f8a-80f7-48ceadf611ef'}

body = json.dumps(payload)

request = http.urlopen('POST', 'http://192.168.2.149:5433/run_trace',
                       body=body, headers=headers)
import pdb; pdb.set_trace()

print request