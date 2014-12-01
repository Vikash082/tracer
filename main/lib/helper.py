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
        mac_Address=dvsport_info.get('macAddress'))
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


def construct_remote_flow(output_action):
    flow_string = 'in_port=1,'
    for elem in output_action:
        m = re.match(r"(?P<key>(mod_vlan_vid|set_tunnel64|"
                     "load|output)[:](?P<value>.*)", elem)
        if m:
            if m.group('key') == 'mod_vlan_vid':
                flow_string += ('dl_vlan=' + m.group('value') + ',')
            elif m.group('key') == 'load':
                remote_ip = get_remote_ip(m.group('value'))
            elif m.group('key') == 'set_tunnel64':
                flow_string += ('tun_id=' + m.group('value') + ',')
    return (remote_ip, flow_string)


def get_remote_ip(ip_string):
    m = re.match(r"(?P<ip>(0[xX][0-9a-fA-F]+)[-,>](?P<rest>.*)")
    ip_addr = ''
    if m:
        ip = m.group('ip')
        for i in xrange(2, len(ip), 2):
            octet = int(ip[i:i + 2])
            ip_addr += (octet + '.')
        return ip_addr[:-1]


def validate_port(port_no, current_chain_index, chain_details):
    if isinstance(chain_details[current_chain_index], list):
        pass