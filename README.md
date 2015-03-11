NVSD Packet tracer project.

Support trace of policy, and flow between VM's of same n/w.

Install:

1. Install Flask on all the nodes where ovs is installed.

    pip install Flask.

2. Copy this app on one of the node from where all the 
   switches are accessible. Install urllib3. Mostly all
   the Ubuntu m/cs will have default installed on it.

3. Go to all the nodes where u have ovs running (compute nodes):

    cd main/compute_app

    python web.py

4. cd main/config.

   Edit config.ini.

   Edit appropriate src_port, dst_port, policy_id, action_id.

   Edit the [REDIS] and [CASSANDRA] sections with proper IP.

   For cassandra, make sure rpc ip should be 0.0.0.0. Check 
   cassandra.yaml file.

5. Go to The NVSD node:

    cd main

    python -m src.control

* action_id was necessary b'coz a policy can have multiple action
  and at a time one can only traverse one path. Earlier version of 
  this code doesn't require action_id input, but expect only one 
  action in the policy.

It can be used without policy also, in that case it will be path
of src and destination without any classifier.

                    OR
6. Use server version. 
7. cd tracer/main
8. python -m src.control
9. Open other terminal. cd tracer/main/test
10. Edit the IP, src_port, dst_port, action_id, policy_id.

Use it and enhance it :)
