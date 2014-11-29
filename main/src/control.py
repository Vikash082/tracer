import ConfigParser
import ast
import json
from pprint import pprint
import pycassa
import redis
import urllib3
from lib.helper import get_action_value_endpoints, get_topology_details


config = ConfigParser.ConfigParser()
topology_info = dict()
config.read("/home/user/tracer/main/config/config.ini")
src_port = config.get("INFO", 'src_port')
dst_port = config.get("INFO", 'dst_port')
policy_id = config.get("INFO", "policy_id")

server = redis.Redis(config.get("REDIS", 'ip'),
                      db=config.get("REDIS", 'db'))
pool = pycassa.pool.ConnectionPool(config.get("CASSANDRA", "keyspace"),
                             server_list=ast.literal_eval(
                                    config.get("CASSANDRA", "servers")),
                             pool_size=5)

policy_info = server.get('nvsd_connectivity_policy:' + policy_id)
policy_info = json.loads(policy_info)

#topology_info[policy_id] = policy_info
#action_list = list()
topology_info['policy'] = policy_id
rule_list = list()
rules = policy_info.get('rules')
topology_info[policy_id + ':rules'] = rules

for rule in rules:
    to_rule = server.get('nvsd_connectivity_rule:' + rule)
    to_rule = json.loads(to_rule)
    topology_info[rule + ":actions"] = to_rule['actions']

topo = list()
topo.append(src_port)
for rule in topology_info[policy_id + ':rules']:
    for action in topology_info[rule + ":actions"]:
        action_info = json.loads(server.get("nvsd_connectivity_action:" +
                                             action))
        chain_list = action_info['chain_list']
        topology_info[action + ':chain_list'] = chain_list
        for node in chain_list:
            left_port, right_port = get_action_value_endpoints(node, server)
            topo.append([left_port, right_port])
        #print action_info

topo.append(dst_port)
topology_info['topology'] = topo

chain_port_details = get_topology_details(topo, server, pycassa, pool)

pprint(chain_port_details)

http = urllib3.PoolManager()
headers = {'content-type': 'application/json'}

payload = json.dumps({'flow_string':'in_port=6,dl_dst=fa:16:3e:32:5b:c8,tcp'})
request = http.urlopen('POST', 'http://192.168.6.74:5433/ofproto-traces',
                       body=payload, headers=headers)


data = json.loads(request.data)

for line in data:
    print "Line : ", line
# res = server.get("mirror_nws_info")
# res = json.loads(res)
# for key in res:
#     print "key: - ", key, "value: -", res[key]
