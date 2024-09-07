import os
import random
import time
from typing import Tuple
import socket

## IMPORTANT
# before starting this, you need to have created a docker network. 
# This is not done automatically as to not potentially block your IP so you can check what IP range is free for you
# example command:

# docker network create --subnet=172.20.0.0/16 dht_network

#wether to only print the run commands
print_mode = False

number_of_containers = 50 # obviously don't start more than 64009. But I also don't think your computer wants you to do that
container_name = "dht_swarm"
network_name = "dht_network"
ip_prefix = f"172.20."
base_module = 7000

added_peers: Tuple[str, int] = [] # saved as pairs of (ip, p2p_port)
__dirname__ = os.path.dirname(__file__)


def start(ip: str, i: int):
    global base_module
    module_port = base_module #+ 2*i
    p2p_port = base_module + 1 #+ 2*i

    if i > 0:
        random_peer = random.choice(added_peers)
        flags =  f" -A {random_peer[0]} -P {random_peer[1]}"
    else:
        flags = ""

    
    print(f"Starting {ip}:{p2p_port}" + (f" that connects to {random_peer[0]}:{random_peer[1]}" if flags else " to create a network") + ":")
    #os.system(f"docker stop dht_swarm_{i}")
    os.system(f"docker rm dht_swarm_{i} --force > /dev/null 2>&1") #disable force if you may want to restart the containers later
    if (print_mode):
        start_command =  f"docker run -it --name dht_swarm_{i} --network dht_network --ip {ip} dht_swarm /server/build/dht_server -a {ip} -m {module_port} -p {p2p_port} " + flags
        print(start_command)
    else: 
        start_command =  f"docker run -d --name dht_swarm_{i} --network dht_network --ip {ip} dht_swarm /server/build/dht_server -a {ip} -m {module_port} -p {p2p_port} " + flags
        status = os.system(start_command)
        if os.WIFEXITED(status):
            if os.WEXITSTATUS(status) == 125: #exit code when address already in use
                print(f"ERROR. Couldn't start container {i}.")
                print(f"ERROR. If network is missing: Read comment at the top of the file")
                print("Maybe tried to bind to address in use? This should not happen in a docker network. (For starting on localhost: increment all port variables by 2 in a loop and try again)")
                return
    added_peers.append((ip, p2p_port))
    

#build docker container
os.system(f"docker build -t dht_swarm {__dirname__}/../..")
#start first container:
start(f"{ip_prefix}0.2", 0)

for i in range (1, number_of_containers):
    subnet = i // 253
    ip_end = i % 253 + 2 # keep addresses between 2 and 254. We are currently assuming all are free and the network is "reserved for us"
    ip = ip_prefix + f"{subnet}.{ip_end}"
    start(ip, i)
    time.sleep(0.5)



