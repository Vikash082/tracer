from flask import Flask, request
app = Flask(__name__)

import sys
from os.path import abspath, dirname
sys.path.insert(0, dirname(dirname(abspath(__file__))))
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
    prepare_expected_packet_path, prepare_tap_expected_path, validate_tap_port

# Install python-tk and watchdog also

class Topology(object):
    def __init__(self):
        self.insertion_mode = self.direction = self.direction1 = \
                        self.direction2 = None
        self.reverse = self.validate_action_id = False
        self.topology_info = dict()
        self.topo = list()
        self.traversed_path = list()

        self.config = ConfigParser.ConfigParser()
        self.config.read("/root/git/tracer/main/config/config.ini")
        self.server = redis.Redis(self.config.get("REDIS", 'ip'),
                              db=self.config.get("REDIS", 'db'))
        self.pool = pycassa.pool.ConnectionPool(self.config.get("CASSANDRA",
                                                            "keyspace"),
                                                server_list=ast.literal_eval(
                                                self.config.get(
                                                    "CASSANDRA", "servers")),
                                                pool_size=5)

    def policy_topology(self, policy_id, action_id, src_port, dst_port):
        policy_info = self.server.get('nvsd_connectivity_policy:' + policy_id)
        policy_info = json.loads(policy_info)
        self.topology_info['policy'] = policy_id
        #rule_list = list()
        rules = policy_info.get('rules')
        left_cg = policy_info.get('left_group')
        right_cg = policy_info.get('right_group')
        self.topology_info[policy_id + ':rules'] = rules
        left_group = json.loads(self.server.get('nvsd_connectivity_portgroup:' +
                                            left_cg))
        left_endpoints = left_group.get('nvsd_connectivity_ports')
    
        for endpoint in left_endpoints:
            endpoint_info = json.loads(self.server.get('nvsd_connectivity_port:' +
                                                   endpoint))
            if dst_port == endpoint_info['port_id']:
                self.direction2 = 'r2l'
    
        right_group = json.loads(self.server.get('nvsd_connectivity_portgroup:' +
                                             right_cg))
        right_endpoints = right_group.get('nvsd_connectivity_ports')
    
        for endpoint in right_endpoints:
            endpoint_info = json.loads(self.server.get('nvsd_connectivity_port:' +
                                                   endpoint))
            if src_port == endpoint_info['port_id']:
                self.direction1 = 'r2l'
    
        if self.direction2 == 'r2l' or self.direction1 == 'r2l':
            self.reverse = True
            self.topo.append(dst_port)
        else:
            self.topo.append(src_port)
    
        for rule in rules:
            to_rule = self.server.get('nvsd_connectivity_rule:' + rule)
            to_rule = json.loads(to_rule)
            self.topology_info[rule + ":actions"] = to_rule['actions']
            self.topology_info[rule + ":classifier"] = to_rule['classifier']
    
        classifier = ''
        for rule in self.topology_info[policy_id + ':rules']:
            for action in self.topology_info[rule + ":actions"]:
                action_info = json.loads(self.server.get("nvsd_connectivity_action:" +
                                                     action))
                if action_id != action_info['id']:
                    continue
                self.validate_action_id = True
                self.insertion_mode = action_info['action_type']
                chain_list = action_info['chain_list']
                self.topology_info[action + ':chain_list'] = chain_list
                for node in chain_list:
                    left_port, right_port = get_action_value_endpoints(node,
                                                                        self.server)
                    if left_port and right_port:
                        self.topo.append([left_port, right_port])
                    elif not right_port:
                        self.topo.append([left_port])
                #print action_info
                classifier_info = json.loads(self.server.get(
                                        'nvsd_connectivity_classifier:'
                                        + self.topology_info[rule + ":classifier"]))

                if classifier_info.get('protocol'):
                    classifier += classifier_info['protocol'].lower()
                else:
                    classifier += 'ip'
                self.direction = classifier_info['direction']
                l4_port = classifier_info['port']
    
        if self.reverse == True:
            self.topo.append(src_port)
        else:
            self.topo.append(dst_port)
        return (l4_port, classifier, self.topo)



class Tracer(Topology):
    def __init__(self, src_port, dst_port, policy_id, action_id):
        self.src_port = src_port
        self.dst_port = dst_port
        self.policy_id = policy_id
        self.action_id = action_id
        self.dst_port_num = []
        self.l4_port = self.action_type = self.expected_path = None
        self.classifier = ''
        self.current_chain_index = 0
        self.encountered_wrong_port = False
        self.tap_port = self.real_dst_port = self.right_group_exist = False
        super(Tracer, self).__init__()
        
    def get_initial_topology(self):        
        if self.policy_id:
            if self.action_id:
                (self.l4_port, self.classifier,
                  self.topology_info['topology']) = self.policy_topology(
                                                            self.policy_id,
                                                            self.action_id,
                                                            self.src_port,
                                                            self.dst_port)
            else:
                raise Exception('Please provide and action_id that belongs to '
                                'policy - %s ' % self.policy_id)
        else:
            self.topo.append(self.src_port)
            self.topo.append(self.dst_port)
            self.topology_info['topology'] = self.topo

#         if not self.classifier:
#             self.classifier = 'ip'
            
        self.chain_details = get_topology_details(self.topo, self.server, pycassa,
                                                   self.pool)
    
        pprint(self.chain_details)
        #src_switch_ip = chain_details[0]['switch_ip']
        if self.policy_id != 'None':
            if not self.validate_action_id:
                raise Exception('Please provide a valid action_id for policy - '
                                '%s ' % self.policy_id)
            if self.insertion_mode == "l2redirect":
                self.expected_path, self.right_group_exist = prepare_expected_packet_path(
                                                    self.chain_details, self.reverse)
            else:
                self.dst_port_num.append(self.chain_details[1][0]['port_num'])
                self.expected_path, self.right_group_exist = prepare_tap_expected_path(
                                                                self.chain_details,
                                                                self.reverse)
            print "---------------", self.expected_path, "----------------------"
        if not self.reverse:
            self.dst_mac = self.chain_details[-1]['mac_Address']
            self.in_port = str(self.chain_details[0]['port_num'])
            self.src_switch_ip = self.get_switch_ip(self.chain_details[0][
                                                                    'switch_ip'])
            self.dst_port_num.append(self.chain_details[-1]['port_num'])
            self.dst_switch_ip = self.chain_details[-1]['switch_ip']
        else:
            self.current_chain_index = -1
            self.dst_mac = self.chain_details[0]['mac_Address']
            self.in_port = str(self.chain_details[-1]['port_num'])
            self.src_switch_ip = self.get_switch_ip(self.chain_details[-1]['switch_ip'])
            self.dst_port_num.append(self.chain_details[0]['port_num'])
            self.dst_switch_ip = self.chain_details[0]['switch_ip']
        
        timestamp = datetime.datetime.fromtimestamp(time.time()).strftime(
                                                        '%Y-%m-%d_%H:%M:%S')
        self.flow_log_file = (self.config.get("LOG", "directory") +
                               str(self.policy_id) +
                               "__" + str(timestamp))
        
        self.traversed_path.append([[self.src_switch_ip], self.in_port])
        
        dump_flow_in_file(self.flow_log_file, self.chain_details)
        initial_flow_string = {'flow_string':
                               'in_port=' + str(self.in_port) +
                               ',' +
                               'dl_dst=' + self.dst_mac +
                               ',' +
                               self.classifier}
        
        initial_flow_string['flow_string'] = self.get_flow_port(
                                                initial_flow_string['flow_string'])
        self.payload = json.dumps(initial_flow_string)
        
        self.http = urllib3.PoolManager()
        self.headers = {'content-type': 'application/json'}
  
    def get_flow_port(self, flow_string):
        if self.policy_id:
            if not self.reverse:
                if self.l4_port:
                    flow_string += ',' + 'tp_dst=' + str(self.l4_port)
            else:
                if self.direction and self.direction.lower() == "bi":
                    if self.l4_port:
                        flow_string += ',' + 'tp_src=' + \
                         str(self.l4_port)
        return flow_string
    
    def get_ovs_action(self, src_switch_ip, payload, headers):
        request = self.http.urlopen('POST', 'http://' + src_switch_ip + ':5433' +
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
    
                dump_flow_in_file(self.flow_log_file, line)
        output_action_list = []
        for action in flow['OpenFlow actions']:
            if re.search(r"(output:[0-9]+)", action):
                output_action_list.append(action.split(','))
    
        return output_action_list
    

    def retrace_tap(self, port_num):
        port_num = str(port_num)
        if not self.reverse:
            flow_string = ('in_port=' + port_num +
                            ',dl_dst=' + self.dst_mac)
            payload = json.dumps({'flow_string':
                    ',' + self.get_flow_port(flow_string)})
            src_ip = self.get_switch_ip(
                self.chain_details[0]['switch_ip'])
        else:
            port_num = str(self.chain_details[-1]['port_num'])
            flow_string = ('in_port=' + port_num +
                            ',dl_dst=' + self.dst_mac)
            payload = json.dumps({'flow_string':
                    ',' + self.get_flow_port(flow_string)})
            src_ip = self.get_switch_ip(
                self.chain_details[-1]['switch_ip'])
        #self.traversed_path.append([[src_ip], port_num])
        return src_ip, payload

    def get_packet_path(self, src_switch_ip, payload):
    #global current_chain_index, headers, dst_switch_ip, insertion_mode
        output_action_lists = self.get_ovs_action(src_switch_ip, payload,
                                                   self.headers)
        for output_action_list in output_action_lists:
            index = [i for i, item in enumerate(output_action_list)
                                    if re.search(r"(output:[0-9]+)", item)]
    
            for i in index:
                #if 'output:1' in output_action_list[i]:
                if 'output:1' == output_action_list[i]:
                    #output_action = flow['OpenFlow actions'][-1].split(',')
    
                    switch_ip, flow_string = construct_remote_flow(
                                                            output_action_list,
                                                            self.dst_mac)
                    # Comment this method if u re running this grom any NVSD
                    # node.
                    switch_ip = self.get_switch_ip(switch_ip)
                    try:
                        if self.insertion_mode:
                            validate_port(1, self.current_chain_index,
                                           self.chain_details,
                                           self.reverse, switch_ip)
                    except:
                        pass
                    self.traversed_path.append([[src_switch_ip], 1])
                    flow_string += ',' + self.classifier
                    payload = json.dumps({'flow_string': ',' +
                                           self.get_flow_port(flow_string)})
                    #src_switch_ip = switch_ip
                    self.get_packet_path(switch_ip, payload)
                else:
        #             index = [i for i, item in enumerate(output_action_list)
        #                       if re.search(r"(output:[0-9]+)", item)]
    
        #             output_port = (re.match(r"(?P<key>(output)[:])(?P<port_no>[0-9]+)",
        #                            output_action_list[index[0]]).group('port_no'))
                    output_port = (re.match(r"(?P<key>(output)[:])"
                                            "(?P<port_no>[0-9]+)",
                                            output_action_list[i]).group(
                                                                'port_no'))
                    output_port = ast.literal_eval(output_port)
    
                    try:
                        if self.insertion_mode:
                            validate_port(output_port, self.current_chain_index,
                                           self.chain_details,
                                           self.reverse)
                    except:
                        """
                        Prepare report here
                        """
                        print ("Port %s also encountered while flow tracing"
                                " on switch %s" % (output_port, src_switch_ip))
                        continue
                    self.current_chain_index = ((self.current_chain_index + 1)
                                            if self.current_chain_index >= 0
                                            else self.current_chain_index - 1)
                    self.traversed_path.append([[src_switch_ip], output_port])
                    if isinstance(self.chain_details[self.current_chain_index], list):
                        current_switch_ip = self.chain_details[self.current_chain_index][0][
                                                                    'switch_ip']
                    else:
                        current_switch_ip = self.chain_details[self.current_chain_index][
                                                                    'switch_ip']
    
                    if (output_port in self.dst_port_num and
                         current_switch_ip == self.dst_switch_ip):
                        break
                        #continue
            #         if output_port != (chain_details[-1]['port_num'] if not reverse
            #                             else chain_details[0]['port_num']):
                    else:
                        flow_string, out_port = construct_flow(self.chain_details,
                                                    self.current_chain_index,
                                                    self.dst_mac, self.reverse,
                                                    output_port)
                        self.traversed_path.append([[src_switch_ip], out_port])
                        flow_string += ',' + self.classifier
                        payload = json.dumps({'flow_string': ','
                                              + self.get_flow_port(flow_string)})
                    self.get_packet_path(src_switch_ip, payload)

    def get_tap_packet_path(self, src_switch_ip, payload):
        output_action_lists = self.get_ovs_action(src_switch_ip, payload,
                                                   self.headers)

        for output_action_list in output_action_lists:
            index = [i for i, item in enumerate(output_action_list)
                                    if re.search(r"(output:[0-9]+)", item)]
    
            for i in index:
                #if 'output:1' in output_action_list[i]:
                if 'output:1' == output_action_list[i]:
                    #output_action = flow['OpenFlow actions'][-1].split(',')
    
                    switch_ip, flow_string = construct_remote_flow(
                                                            output_action_list,
                                                            self.dst_mac)
                    # Comment this method if u re running this on any NVSD
                    # node.
                    switch_ip = self.get_switch_ip(switch_ip)
                    try:
                        if self.insertion_mode:
                            validate_tap_port(1, self.current_chain_index,
                                           self.chain_details,
                                           self.reverse,
                                           self.dst_port_num,
                                           switch_ip)
                    except:
                        pass
                    self.traversed_path.append([[src_switch_ip], 1])
                    flow_string += ',' + self.classifier
                    payload = json.dumps({'flow_string': ',' +
                                           self.get_flow_port(flow_string)})
                    #src_switch_ip = switch_ip
                    self.get_tap_packet_path(switch_ip, payload)
                else:
                    output_port = (re.match(r"(?P<key>(output)[:])"
                                            "(?P<port_no>[0-9]+)",
                                            output_action_list[i]).group(
                                                                'port_no'))
                    output_port = ast.literal_eval(output_port)
                    try:
                        if not self.check_output_port(output_action_list):
                            break
                        if (self.current_chain_index == -1 and
                             output_port != self.chain_details[0][
                                                            'port_num']):
                            if self.check_port_in_dest(output_port):
                                self.tap_port = True
                                self.traversed_path.append([[src_switch_ip],
                                                            output_port])
                                continue
                        elif (self.current_chain_index == -1 and
                             output_port == self.chain_details[0][
                                                            'port_num']):
                            if self.check_port_in_dest(output_port):
                                self.real_dst_port = True
                                self.traversed_path.append([[src_switch_ip],
                                                            output_port])
                                continue
                        elif (self.current_chain_index == 0 and
                               output_port != self.chain_details[-1][
                                                                'port_num']):
                            if self.check_port_in_dest(output_port):
                                self.tap_port = True
                                self.traversed_path.append([[src_switch_ip],
                                                            output_port])
                                continue
                        elif (self.current_chain_index == 0 and
                               output_port == self.chain_details[-1][
                                                                'port_num']):
                            if self.check_port_in_dest(output_port):
                                self.real_dst_port = True
                                self.traversed_path.append([[src_switch_ip],
                                                            output_port])
                                continue
                        else:
                            print ("Port %s also encountered while flow tracing"
                                    " on switch %s" % (output_port, src_switch_ip))
                            continue
                    except:
                        raise
        if not self.real_dst_port:
            if self.reverse and self.right_group_exist:
                src_ip, payload = self.retrace_tap(self.chain_details[-1][
                                                                'port_num'])
            elif not self.reverse and self.right_group_exist:
                src_ip, payload = self.retrace_tap(self.chain_details[0][
                                                                'port_num'])
            else:
                return
            self.get_tap_packet_path(src_ip, payload)

    def check_port_in_dest(self, port):
        if port in self.dst_port_num:
            self.dst_port_num.remove(port)
            return True
        else:
            return False

    def check_output_port(self, output_action_list):
        output_port_list = list()
        index = [i for i, item in enumerate(output_action_list)
                                if re.search(r"(output:[0-9]+)", item)]
        
        for i in index:
            output_port = (re.match(r"(?P<key>(output)[:])"
                                    "(?P<port_no>[0-9]+)",
                                    output_action_list[i]).group(
                                                        'port_no'))
            output_port_list.append(ast.literal_eval(output_port))
        
        l = set(self.dst_port_num).intersection(set(output_port_list))
        if l:
            return True
        else:
            False
  
    def start_tracing(self):
        if self.insertion_mode.lower() == 'tap':
            self.get_tap_packet_path(self.src_switch_ip, self.payload)
        else:
            self.get_packet_path(self.src_switch_ip, self.payload)
#         if self.insertion_mode.lower() == 'tap':
#             if self.dst_port_num:
#                 import pdb; pdb.set_trace()
#                 src_ip, payload = self.retrace_tap(self.dst_port_num[0])
#                 self.get_packet_path(src_ip, payload)
        
    def print_path_in_console(self):
        print "\n"
        print "++++++++++++++traversed_path+++++++++++++++++"
        for hop in self.traversed_path:
            print "hop", hop, "=====> ",
        print "\n\n"
     
        if self.policy_id:
            print "--------------expected_path------------------"
            for hop in self.expected_path:
                print "hop", hop, "=====> ",
        print "\n\n"
        print (" ******** Find the flow dump in --->", self.flow_log_file,
                "   *************")
        
    # This is required only for my testing. It will not
    # go in production
    def get_switch_ip(self, switch_ip):
        if switch_ip == "90.90.90.93":
            switch_ip = '192.168.6.93'
        elif switch_ip == "90.90.90.94":
            switch_ip = '192.168.6.94'
        elif switch_ip == "100.10.10.74":
            switch_ip = '192.168.6.74'
        return switch_ip

@app.route("/run_trace", methods=['POST'])
def execute_tracer():
    body = request.json
    src_port = body['src_port']
    dst_port = body['dst_port']
    policy_id = body['policy_id']
    action_id = body['action_id']
    tr = Tracer(src_port, dst_port, policy_id, action_id)
    tr.get_initial_topology()
    tr.start_tracing()
    response = dict()
    response['traversed_path'] = tr.traversed_path
    response['expected_path'] = tr.expected_path
    tr.print_path_in_console()
    return json.dumps(response)
    
if __name__ == '__main__':
#     src_port = 'dbe25e20-00c5-4322-b796-54142f2bee29'
#     dst_port = '587a730b-24e2-4589-aa9b-b9b55e154881'
#     policy_id = '9bf24125-4cff-403e-96f9-d94e9c758af4'
#     action_id = '4abd2275-1d43-4df7-8622-19f7aa5b9db6'
#     #import pdb; pdb.set_trace()
#     tr = Tracer(src_port, dst_port, policy_id, action_id)
#     tr.get_initial_topology()
#     tr.start_tracing()
#     tr.print_path_in_console()
    #import pdb; pdb.set_trace()
    app.run('0.0.0.0', 5433, debug=True)
