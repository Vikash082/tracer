import ast
import json
import re
from lib import constants


def get_action_value_endpoints(action_value, server):
    '''
    If left port is present and right port is not present, then
    right port is left port. If both are not present then use
    service
    '''
    left_ep = right_ep = None
    if action_value.get('left_port', None):
        left_ep = action_value['left_port']
        if action_value.get('right_port', None):
            right_ep = action_value['right_port']
        else:
            right_ep = left_ep
    elif action_value.get('service', None):
        service_obj = json.loads(server.get("service:" +
                                             action_value['service']))
        if service_obj[constants.KEY_INSERTION_MODE].upper() in ['L2',
                                                                 'TAP']:
            left_ep, right_ep = _get_service_endpoints(
                action_value['service'],
                server,
                insertion_mode=service_obj[constants.KEY_INSERTION_MODE])
        else:
            left_ep, right_ep = \
                _get_service_endpoints(action_value['service'], server,
                insertion_mode=service_obj[constants.KEY_INSERTION_MODE])
    return (left_ep, right_ep)


def _get_service_endpoints(service, server, tenant_id=None,
                                         insertion_mode=None):
    left_ep = right_ep = None
    service_instances = list(server.smembers(service + ":instances_list"))
    instance_obj = server.get(service_instances[0] + ":info")
    if (type(instance_obj) != dict):
        instance_obj = ast.literal_eval(instance_obj)

    if insertion_mode and insertion_mode.lower() == "tap":
        left_ep = instance_obj['left_real_port_id']
    elif insertion_mode and insertion_mode.lower() == "l2":
        left_ep = instance_obj['left_real_port_id']
        right_ep = instance_obj['right_real_port_id']
    else:
        left_nic = instance_obj["left_nic"]
        left_ep = left_nic[0]["port_id"]
        right_nic = instance_obj.get("right_nic", None)
        if right_nic:
            right_ep = right_nic[0].get("port_id")

    return (left_ep, right_ep)


def get_port_details(port_id, port_col_obj):
        dvsport_info = port_col_obj.get(port_id)
        port_details = dict(
        switch_ip=dvsport_info.get('switchIp'),
        vm_ip=dvsport_info.get('vmIpAddress'),
        port_state=dvsport_info.get('dvsPortState'),
        port_num=dvsport_info.get('ovsPortNum'),
        port_name=dvsport_info.get('ovsPortName'),
        mac_Address=dvsport_info.get('macAddress'),
        port_id=port_id)
        return port_details


def get_topology_details(topo, redis, pycassa_obj, cassandra_pool):
    dvsport_col = pycassa_obj.ColumnFamily(cassandra_pool, 'DVSPort')
    port_details = list()
    for port in topo:
        if isinstance(port, list):
            l = list()
            for port_id in port:
                l.append(get_port_details(port_id, dvsport_col))
            port_details.append(l)
        else:
            port_details.append(get_port_details(port, dvsport_col))
    return port_details


def construct_remote_flow(output_action, dst_mac):
    flow_string = 'in_port=1,dl_dst=' + dst_mac + ','
    remote_ip = None
    for elem in output_action:
        m = re.match(r"(?P<key>(mod_vlan_vid|set_tunnel64|"
                     "load|output))[:](?P<value>.*)", elem)
        if m:
            if m.group('key') == 'mod_vlan_vid':
                flow_string += ('dl_vlan=' + m.group('value') + ',')
            elif m.group('key') == 'load':
                remote_ip = get_remote_ip(m.group('value'))
            elif m.group('key') == 'set_tunnel64':
                flow_string += ('tun_id=' + m.group('value') + ',')
    return (remote_ip, flow_string)


def get_remote_ip(ip_string):
    m = re.match(r"(?P<ip>(0[xX][0-9a-fA-F]+))[-,>](?P<rest>.*)", ip_string)
    ip_addr = ''
    if m:
        ip = m.group('ip')
        for i in xrange(2, len(ip), 2):
            octet = int(ip[i:i + 2], 16)
            ip_addr += (str(octet) + '.')
        return ip_addr[:-1]


def construct_flow(chain_details, current_chain_index, dst_mac, reverse,
                   in_port):
    #in_port = ast.literal_eval(in_port)
    if not reverse:
        if isinstance(chain_details[current_chain_index], list):
            if in_port == chain_details[current_chain_index][0]['port_num']:
                # Considering only the case of L2
                out_port = chain_details[current_chain_index][1]['port_num']
    else:
        if isinstance(chain_details[current_chain_index], list):
            if in_port == chain_details[current_chain_index][-1]['port_num']:
                # Considering only the case of L2
                out_port = chain_details[current_chain_index][0]['port_num']
    # We don't require mac here.
    flow_string = "in_port=" + str(out_port) + ",dl_dst=" + dst_mac
    return flow_string, out_port


def validate_port(port_no, current_chain_index, chain_details, reverse,
                  remote_switch_ip=None):
    #port_no = ast.literal_eval(port_no)
    hop = chain_details[current_chain_index]
    if isinstance(hop, list):
        hop_ip = hop[0]['switch_ip']
    else:
        hop_ip = hop['switch_ip']
    if reverse:
        if (current_chain_index - 1) > 0:
            raise Exception("Fatal Error")
        else:
            next_hop = chain_details[current_chain_index - 1]
    else:
        if (current_chain_index + 1) >= len(chain_details):
            raise Exception("Fatal Error")
        else:
            next_hop = chain_details[current_chain_index + 1]
    if port_no == 1:
        if isinstance(next_hop, list):
            next_hop_ip = next_hop[-1]['switch_ip']
        else:
            next_hop_ip = next_hop['switch_ip']
        #if hop_ip == next_hop_ip or remote_switch_ip == next_hop_ip:
        if hop_ip == next_hop_ip or remote_switch_ip == next_hop_ip:
            raise Exception("Issue with flow configuration or classifier")
    else:
        if not reverse:
            if isinstance(next_hop, list):
                next_hop_port = next_hop[0]['port_num']
            else:
                next_hop_port = next_hop['port_num']
        else:
            if isinstance(next_hop, list):
                next_hop_port = next_hop[-1]['port_num']
            else:
                next_hop_port = next_hop['port_num']
        if next_hop_port != port_no:
            raise Exception("Output port did not match with the topology")


def dump_flow_in_file(filename, content):
    with open(filename, 'a+b') as logfile:
        logfile.write(content)


def prepare_expected_packet_path(chain_details, reverse):
    port_chain = []
    next_switch_ip = None
    if not reverse:
        for i in range(0, len(chain_details)):
            if i + 1 < len(chain_details):
                next_switch_ip = (chain_details[i + 1][0]['switch_ip']
                                  if isinstance(chain_details[i + 1], list)
                                   else chain_details[i + 1]['switch_ip'])
            if isinstance(chain_details[i], list):
                if next_switch_ip != chain_details[i][0]['switch_ip']:
                    port_chain.append([[chain_details[i][0]['switch_ip']],
                                       chain_details[i][0]['port_num']])
                    port_chain.append([[chain_details[i][0]['switch_ip']],
                                       chain_details[i][1]['port_num']])
                    port_chain.append([[chain_details[i][0]['switch_ip']],
                                       1])
                else:
                    port_chain.append([[chain_details[i][0]['switch_ip']],
                                       chain_details[i][0]['port_num']])
                    port_chain.append([[chain_details[i][0]['switch_ip']],
                                       chain_details[i][1]['port_num']])
            else:
                if next_switch_ip != chain_details[i]['switch_ip']:
                    port_chain.append([[chain_details[i]['switch_ip']],
                                       chain_details[i]['port_num']])
                    port_chain.append([[chain_details[i]['switch_ip']],
                                        1])
                else:
                    port_chain.append([[chain_details[i]['switch_ip']],
                                       chain_details[i]['port_num']])
    else:
        i = -1
        while i >= (-len(chain_details)):
            #import pdb; pdb.set_trace()
            if (i - 1) >= (-len(chain_details)):
                next_switch_ip = (chain_details[i - 1][0]['switch_ip']
                                  if isinstance(chain_details[i - 1], list)
                                   else chain_details[i - 1]['switch_ip'])
            if isinstance(chain_details[i], list):
                if next_switch_ip != chain_details[i][0]['switch_ip']:
                    port_chain.append([[chain_details[i][0]['switch_ip']],
                                       chain_details[i][-1]['port_num']])
                    port_chain.append([[chain_details[i][0]['switch_ip']],
                                       chain_details[i][0]['port_num']])
                    port_chain.append([[chain_details[i][0]['switch_ip']],
                                       1])
                else:
                    port_chain.append([[chain_details[i][0]['switch_ip']],
                                       chain_details[i][-1]['port_num']])
                    port_chain.append([[chain_details[i][0]['switch_ip']],
                                       chain_details[i][0]['port_num']])
            else:
                if next_switch_ip != chain_details[i]['switch_ip']:
                    port_chain.append([[chain_details[i]['switch_ip']],
                                       chain_details[i]['port_num']])
                    port_chain.append([[chain_details[i]['switch_ip']],
                                       1])
                else:
                    port_chain.append([[chain_details[i]['switch_ip']],
                                       chain_details[i]['port_num']])
            print port_chain
            i -= 1

    print "--------", port_chain, "---------"
    return port_chain


def prepare_tap_expected_path(chain_details, reverse):
    port_chain = []
    tap_switch_ip = chain_details[1][0]['switch_ip']
    if not reverse:
        src_switch_ip = chain_details[0]['switch_ip']
        dst_switch_ip = chain_details[-1]['switch_ip']
        if src_switch_ip == tap_switch_ip:
            tap_path = [[src_switch_ip], chain_details[0]['port_num'],
                        [src_switch_ip], chain_details[1][0]['port_num']]
        else:
            tap_path = [[src_switch_ip], chain_details[0]['port_num'],
                        [src_switch_ip], 1,
                        [tap_switch_ip], chain_details[1][0]['port_num']]

        if src_switch_ip == dst_switch_ip:
            dst_path = [[src_switch_ip], chain_details[0]['port_num'],
                        [src_switch_ip], chain_details[-1]['port_num']]
        else:
            dst_path = [[src_switch_ip], chain_details[0]['port_num'],
                        [src_switch_ip], 1,
                        [tap_switch_ip], chain_details[-1]['port_num']]
    else:
        src_switch_ip = chain_details[-1]['switch_ip']
        dst_switch_ip = chain_details[0]['switch_ip']
        if src_switch_ip == tap_switch_ip:
            tap_path = [[src_switch_ip], chain_details[-1]['port_num'],
                        [src_switch_ip], chain_details[-2][0]['port_num']]
        else:
            tap_path = [[src_switch_ip], chain_details[-1]['port_num'],
                        [src_switch_ip], 1,
                        [tap_switch_ip], chain_details[-2][0]['port_num']]

        if src_switch_ip == dst_switch_ip:
            dst_path = [[src_switch_ip], chain_details[-1]['port_num'],
                        [src_switch_ip], chain_details[0]['port_num']]
        else:
            dst_path = [[src_switch_ip], chain_details[-1]['port_num'],
                        [src_switch_ip], 1,
                        [tap_switch_ip], chain_details[0]['port_num']]

    port_chain.append(tap_path)
    port_chain.append(dst_path)
    return port_chain
