from flask import Flask, request
import json
from subprocess import Popen, PIPE


app = Flask(__name__)


@app.route("/ofproto-traces", methods=['POST'])
def execute_ofproto_trace():
    body = request.json
    res = Popen(["ovs-appctl", "ofproto/trace", "br-int", body["flow_string"]],
                 stdout=PIPE)
    return json.dumps(res.communicate())


if __name__ == '__main__':
    app.run('192.168.6.0', 5433, debug=True)
