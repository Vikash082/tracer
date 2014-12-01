import ConfigParser
import ast
import json
from pprint import pprint
import pycassa
import re
import redis
import urllib3

from lib.helper import get_action_value_endpoints, get_topology_details, \
    construct_remote_flow, validate_port


config = ConfigParser.ConfigParser()
topology_info = dict()
config.read("/home/guess/tracer/main/config/config.ini")
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

chain_details = get_topology_details(topo, server, pycassa, pool)

pprint(chain_details)
#node_ip = chain_details[0]['switch_ip']
node_ip = '192.168.6.74'
payload = json.dumps({'flow_string':
                       'in_port=' + str(chain_details[0]['port_num']) +
                       ',' +
                       'dl_dst=' + str(chain_details[-1]['mac_Address']) +
                       ',' +
                       config.get("INFO", "classifier_protocol")})


http = urllib3.PoolManager()
headers = {'content-type': 'application/json'}
import pdb; pdb.set_trace()
current_chain_index = 0

while True:
    #payload = json.dumps({'flow_string':'in_port=6,dl_dst=fa:16:3e:32:5b:c8,tcp'})
    request = http.urlopen('POST', 'http://' + node_ip + ':5433' +
                            '/ofproto-traces',
                            body=payload, headers=headers)

    data = json.loads(request.data)
    #pprint (data)
    flow = dict()
    #reg = 'Flow:|Rule:|OpenFlow actions:|Resubmitted flow:|Resubmitted regs:|Final flow:|Datapath actions:'
    for line in data:
        if line:
            print "Line : ", line
            res = line.split('\n')
            for i in res:
                #import pdb; pdb.set_trace()
                m = re.match(r"([\t])*(?P<key>(Flow|Rule|OpenFlow actions|"
                             "Resubmitted flow|Resubmitted regs|Final flow|"
                             "Datapath actions))[:,=]\s?(?P<value>.*)", i)
                if m:
                    if flow.get(m.group('key')):
                        flow[m.group('key')].append(m.group('value'))
                    else:
                        flow[m.group('key')] = [m.group('value')]
                        #print m.group('key'), m.group('value')
    output_action_list = flow['OpenFlow actions'][-1].split(',')
    if 'output:1' in output_action_list:
        #output_action = flow['OpenFlow actions'][-1].split(',')
        validate_port(1, current_chain_index, chain_details)
        switch_ip, flow_string = construct_remote_flow(output_action_list)
        payload = json.dumps({'flow_string': flow_string +
                               'dl_dst=' +
                               str(chain_details[-1]['mac_Address'])})
        node_ip = switch_ip
    else:
        index = [i for i, item in enumerate(output_action_list)
                  if re.search(r"(output:[0-9]+)", item)]
        output_port = (re.match(r"(?P<key>(output)[:])(?P<port_no>[0-9]+)")
                       ).group('port_no')
        current_chain_index += 1
        try:
            validate_port(output_port, current_chain_index, chain_details)
        except:
            pass

pprint(flow)
# if 'output:1' in flow['OpenFlow actions'][-1].split():
#     output_action = flow['OpenFlow actions'][-1].split(',')
#     print "Final output === > ", flow['OpenFlow actions'][-1].split(',')
#     construct_remote_flow(output_action)
