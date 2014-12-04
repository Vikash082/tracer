import ConfigParser
import ast
import datetime
import json
from pprint import pprint
import pycassa
import re
import redis
import time
import urllib3

from lib.helper import get_action_value_endpoints, get_topology_details, \
    construct_remote_flow, validate_port, construct_flow, dump_flow_in_file, \
    prepare_expected_packet_path, prepare_tap_expected_path


def get_switch_ip(switch_ip):
    if switch_ip == "90.90.90.93":
        original_switch_ip = '192.168.6.93'
    elif switch_ip == "90.90.90.94":
        original_switch_ip = '192.168.6.94'
    elif switch_ip == "100.10.10.74":
        original_switch_ip = '192.168.6.74'
    return original_switch_ip


config = ConfigParser.ConfigParser()
topology_info = dict()
config.read("/home/guess/tracer/main/config/config.ini")
src_port = config.get("INFO", 'src_port')
dst_port = config.get("INFO", 'dst_port')
policy_id = config.get("INFO", "policy_id")
reverse = False
action_type = None
direction1 = direction2 = None
topo = list()
traversed_path = []
dst_port_num = []
insertion_mode = None
classifier = config.get("INFO", "classifier")

server = redis.Redis(config.get("REDIS", 'ip'),
                      db=config.get("REDIS", 'db'))
pool = pycassa.pool.ConnectionPool(config.get("CASSANDRA", "keyspace"),
                             server_list=ast.literal_eval(
                                    config.get("CASSANDRA", "servers")),
                             pool_size=5)


#topology_info[policy_id] = policy_info
#action_list = list()

def policy_topology(policy_id):
    global insertion_mode
    policy_info = server.get('nvsd_connectivity_policy:' + policy_id)
    policy_info = json.loads(policy_info)
    topology_info['policy'] = policy_id
    rule_list = list()
    rules = policy_info.get('rules')
    left_cg = policy_info.get('left_group')
    right_cg = policy_info.get('right_group')
    topology_info[policy_id + ':rules'] = rules
    left_group = json.loads(server.get('nvsd_connectivity_portgroup:' +
                                        left_cg))
    left_endpoints = left_group.get('nvsd_connectivity_ports')

    for endpoint in left_endpoints:
        endpoint_info = json.loads(server.get('nvsd_connectivity_port:' +
                                               endpoint))
        if dst_port == endpoint_info['port_id']:
            direction2 = 'r2l'

    right_group = json.loads(server.get('nvsd_connectivity_portgroup:' +
                                         right_cg))
    right_endpoints = right_group.get('nvsd_connectivity_ports')

    for endpoint in right_endpoints:
        endpoint_info = json.loads(server.get('nvsd_connectivity_port:' +
                                               endpoint))
        if src_port == endpoint_info['port_id']:
            direction1 = 'r2l'

    if direction2 == 'r2l' or direction1 == 'r2l':
        reverse = True
        topo.append(dst_port)
    else:
        topo.append(src_port)

    for rule in rules:
        to_rule = server.get('nvsd_connectivity_rule:' + rule)
        to_rule = json.loads(to_rule)
        topology_info[rule + ":actions"] = to_rule['actions']

    for rule in topology_info[policy_id + ':rules']:
        for action in topology_info[rule + ":actions"]:
            action_info = json.loads(server.get("nvsd_connectivity_action:" +
                                                 action))
            insertion_mode = action_info['action_type']
            chain_list = action_info['chain_list']
            topology_info[action + ':chain_list'] = chain_list
            for node in chain_list:
                left_port, right_port = get_action_value_endpoints(node,
                                                                    server)
                if left_port and right_port:
                    topo.append([left_port, right_port])
                elif not right_port:
                    topo.append([left_port])
            #print action_info

    if reverse == True:
        topo.append(src_port)
    else:
        topo.append(dst_port)
    return topo

# Thats a crapy comparison. ConfigParser sucks.
if policy_id != 'None':
    topology_info['topology'] = policy_topology(policy_id)
else:
    topo.append(src_port)
    topo.append(dst_port)
    topology_info['topology'] = topo

chain_details = get_topology_details(topo, server, pycassa, pool)

pprint(chain_details)
#src_switch_ip = chain_details[0]['switch_ip']

if policy_id != 'None':
    if insertion_mode == "l2redirect":
        expected_path = prepare_expected_packet_path(chain_details, reverse)
    else:
        dst_port_num.append(chain_details[1][0]['port_num'])
        expected_path = prepare_tap_expected_path(chain_details, reverse)
    print "---------------", expected_path, "----------------------"

if not reverse:
    current_chain_index = 0
    dst_mac = chain_details[-1]['mac_Address']
    in_port = str(chain_details[0]['port_num'])
    src_switch_ip = get_switch_ip(chain_details[0]['switch_ip'])
    dst_port_num.append(chain_details[-1]['port_num'])
    dst_switch_ip = chain_details[-1]['switch_ip']
else:
    current_chain_index = -1
    dst_mac = chain_details[0]['mac_Address']
    in_port = str(chain_details[-1]['port_num'])
    src_switch_ip = get_switch_ip(chain_details[-1]['switch_ip'])
    dst_port_num.append(chain_details[0]['port_num'])
    dst_switch_ip = chain_details[0]['switch_ip']

timestamp = datetime.datetime.fromtimestamp(time.time()).strftime(
                                                '%Y-%m-%d_%H:%M:%S')
flow_log_file = (config.get("LOG", "directory") + str(policy_id) +
                     "__" + str(timestamp))

traversed_path.append([[src_switch_ip], in_port])

initial_flow_string = {'flow_string':
                       'in_port=' + str(in_port) +
                       ',' +
                       'dl_dst=' + dst_mac}
#                        ',' +
#                        config.get("INFO", "classifier")}

if classifier:
    initial_flow_string['flow_string'] += ',' + classifier

payload = json.dumps(initial_flow_string)

http = urllib3.PoolManager()
headers = {'content-type': 'application/json'}
#flow = dict()


def get_ovs_action(src_switch_ip, payload, headers):
#while True:
    request = http.urlopen('POST', 'http://' + src_switch_ip + ':5433' +
                            '/ofproto-traces',
                            body=payload, headers=headers)
    data = json.loads(request.data)
    flow = dict()
    #pprint (data)
    for line in data:
        if line:
            print "Line : ", line
            res = line.split('\n')
            for i in res:
                m = re.match(r"([\t])*(?P<key>(Flow|Rule|OpenFlow actions|"
                             "Resubmitted flow|Resubmitted regs|Final flow|"
                             "Datapath actions))[:,=]\s?(?P<value>.*)", i)
                if m:
                    if flow.get(m.group('key')):
                        flow[m.group('key')].append(m.group('value'))
                    else:
                        flow[m.group('key')] = [m.group('value')]

            dump_flow_in_file(flow_log_file, line)
    output_action_list = []

    for action in flow['OpenFlow actions']:
        if re.search(r"(output:[0-9]+)", action):
            output_action_list.append(action.split(','))

    return output_action_list


def get_packet_path(src_switch_ip, payload):
    global current_chain_index, headers, dst_switch_ip
    output_action_lists = get_ovs_action(src_switch_ip, payload, headers)

    for output_action_list in output_action_lists:
        index = [i for i, item in enumerate(output_action_list)
                                if re.search(r"(output:[0-9]+)", item)]

        for i in index:
            #if 'output:1' in output_action_list[i]:
            if 'output:1' == output_action_list[i]:
                #output_action = flow['OpenFlow actions'][-1].split(',')

                switch_ip, flow_string = construct_remote_flow(
                                                        output_action_list,
                                                        dst_mac)
                switch_ip = get_switch_ip(switch_ip)
                try:
                    validate_port(1, current_chain_index, chain_details,
                                   reverse, switch_ip)
                except:
                    pass
                traversed_path.append([[src_switch_ip], 1])

                payload = json.dumps({'flow_string': flow_string + ',' +
                                      classifier})
                src_switch_ip = switch_ip
                get_packet_path(src_switch_ip, payload)
            else:
    #             index = [i for i, item in enumerate(output_action_list)
    #                       if re.search(r"(output:[0-9]+)", item)]

    #             output_port = (re.match(r"(?P<key>(output)[:])(?P<port_no>[0-9]+)",
    #                            output_action_list[index[0]]).group('port_no'))
                output_port = (re.match(r"(?P<key>(output)[:])(?P<port_no>[0-9]+)",
                               output_action_list[i]).group('port_no'))
                output_port = ast.literal_eval(output_port)

                try:
                    validate_port(output_port, current_chain_index, chain_details,
                                  reverse)
                except:
                    """
                    Prepare report here
                    """
                    # Verify once.
                    if insertion_mode.lower() == 'tap':
                        if (current_chain_index == -1 and
                             output_port != chain_details[0]['port_num']):
                            raise
                        elif (current_chain_index == 0 and
                               output_port != chain_details[-1]['port_num']):
                            raise
                        else:
                            traversed_path.append([[src_switch_ip],
                                                    output_port])
                            dst_switch_ip = chain_details[1][0]['switch_ip']
                            break

                current_chain_index = ((current_chain_index + 1)
                                        if current_chain_index >= 0
                                        else current_chain_index - 1)
                traversed_path.append([[src_switch_ip], output_port])
                if isinstance(chain_details[current_chain_index], list):
                    current_switch_ip = chain_details[current_chain_index][0]['switch_ip']
                else:
                    current_switch_ip = chain_details[current_chain_index]['switch_ip']

                if (output_port in dst_port_num and
                     current_switch_ip == dst_switch_ip):
                    break
        #         if output_port != (chain_details[-1]['port_num'] if not reverse
        #                             else chain_details[0]['port_num']):
                else:
                    flow_string, out_port = construct_flow(chain_details,
                                                current_chain_index,
                                                dst_mac, reverse, output_port)
                    traversed_path.append([[src_switch_ip], out_port])
                    payload = json.dumps({'flow_string': flow_string + ','
                                          + classifier})
                get_packet_path(src_switch_ip, payload)

get_packet_path(src_switch_ip, payload)

#pprint(flow)

print "\n"

print "++++++++++++++traversed_path+++++++++++++++++"
for hop in traversed_path:
    print "hop", hop, "=====> ",
print "\n\n"

if policy_id != 'None':
    print "--------------expected_path------------------"
    for hop in expected_path:
        print "hop", hop, "=====> ",
