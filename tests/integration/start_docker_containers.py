import os
import string
import subprocess
import threading
import time
import socket
import random
from typing import Dict, Tuple

import dht_client

# maps peer_id to (ip, port)
added_peers: Dict[int, Tuple[str, int]] = {}
__dirname__ = os.path.dirname(__file__)
print_lock = threading.Lock()


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

host_ip = get_local_ip()

def start(command, i):
    print(f"Starting peer {i + 1}: {os.path.basename(command)}") # basename works because: "This is the second element of the pair returned by passing path to the function split()" and we only have one / in output
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    threading.Thread(target=log_output, args=(process, f"Node {i + 1}", print_lock), daemon=True).start()
    return process

def log_output(process, prefix, lock):
    for line in iter(process.stdout.readline, b''):
        if line:
            with lock:
                print(f"{prefix}: {line.decode('utf-8', errors='replace').strip()}")

def start_peer_container(ip: str, i: int):
    global verify_peer
    global base_module
    module_port = base_module
    p2p_port = base_module + 1

    expose_ports_flags = ""
    if i > 0:
        random_peer_id = random.choice(list(added_peers.keys()))
        random_peer = added_peers[random_peer_id]
        flags = f"-A {random_peer[0]} -P {random_peer[1]}"
    else:
        expose_ports_flags = f" -p {module_port}:{module_port} -p {p2p_port}:{p2p_port} "
        flags = ""
    os.system(f"docker rm dht_swarm_{i} --force > /dev/null 2>&1")

    print(f"Starting {ip}:{p2p_port}" + (f" that connects to {random_peer[0]}:{random_peer[1]}" if flags else " to create a network") + ":")

    start_command =  f"docker run {expose_ports_flags} -t --name dht_swarm_{i} --network {network_name} --ip {ip} dht_swarm /server/build/dht_server -a {ip} -m {module_port} -p {p2p_port} {flags} -l {loglevel}"

    if verify_peer:
        start_command += f" -v"
    start_command = start_command.strip()

    if (print_mode):
        print(start_command)
    else:
        start(start_command, i)

    added_peers[i] = (ip, p2p_port)


def start_network(n_peers):
    os.system(f"docker network inspect {network_name} > /dev/null 2>&1 || docker network create --subnet={ip_prefix}0.0/16 {network_name}")
    start_peer_container(f"{ip_prefix}0.2", 0)
    time.sleep(0.5)

    for i in range(1, n_peers):
        subnet = i // 253
        ip_end = i % 253 + 2  # Keep addresses between 2 and 254
        ip = f"{ip_prefix}{subnet}.{ip_end}"
        start_peer_container(ip, i)
        time.sleep(0.2)


def close_modules_randomly(number):
    to_close = min(number, len(added_peers))
    for _ in range(to_close):
        random_peer_id = random.choice(list(added_peers.keys()))
        random_peer = added_peers[random_peer_id]
        os.system(f"docker stop dht_swarm_{random_peer_id}")
        print(f"Closed peer {random_peer[0]}:{random_peer[1]}")


def close_all_peers():
    for peer_i, (peer_ip, peer_port) in added_peers.items():
        container = f"dht_swarm_{peer_i}"
        os.system(f"docker stop {container}")
        print(f"Closed peer {peer_ip}:{peer_port}")


def close_peer(peer_i):
    if peer_i in added_peers:
        peer_ip, peer_port = added_peers[peer_i]
        container = f"dht_swarm_{peer_i}"
        os.system(f"docker stop {container}")
        print(f"Closed peer {peer_ip}:{peer_port}")

def random_string(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def get_ip_for_index(i):
    subnet = i // 253
    ip_end = i % 253 + 2  # Keep addresses between 2 and 254
    ip = f"{ip_prefix}{subnet}.{ip_end}"
    return ip



# GUIDE #
print("""If you want to start many nodes with docker containers you can run the start_network function with the appropriate number.
      
You can also set "print_mode" in the parameters below to True, which will only print the docker run commands instead of executing them. This is useful if you want to directly modify the commands or open multiple terminals with a started server to see how they interact. With loglevel set to debug you can see exactly what's going on the servers.
      
The containers open their module ports on 'base_module' and their p2p ports on 'base_module' + 1. (Set in this file, default is 7401)
      
Set print mode to False if you want to run the tests. Else, set it to true if you only need commands to be printed and want to start the containers manually
      
Keep in mind to set an appropriate log level in this file just below this text. If you want to run tests where many Nodes start or want to test how many nodes can start without your pc crashing (many :D, at least for us) you can also set it to off.

On the first execution, this will print a few example docker commands:
""")

#-------- PARAMETERS --------#
network_name = "dht_network"
ip_prefix = "172.20."
number_of_containers = 4
base_module = 7401

loglevel = "info"  # can be trace|debug|info|warn|err|critical|off
verify_peer = False
print_mode = False
#--------#--------#---------#


if print_mode:
    print("Warning, Print mode is enabled, we do not run any tests. All commands are only displayed, not run.")
    start_network(number_of_containers)
    exit()


os.system(f"docker build -t dht_swarm {__dirname__}/../..")
os.system("docker stop $(docker ps -q)")

print("#-------------TESTING--------------#")


print("\nTEST 1 | DHT_GET: Single node should return DHT_FAILURE if value is not saved")
start_network(0)
time.sleep(2)
s = dht_client.get_socket(host_ip, base_module)
dht_client.send_get(s, dht_client.dht_key)
s.close()
close_all_peers()


print("\nTEST 2 | DHT_PUT -> DHT_GET: Single node should return DHT_SUCCESS if saved value is retrieved")
start_network(0)
time.sleep(2)
value = bytes("Landwirtschaft braucht Zeit und Platz", encoding='utf=8')
s = dht_client.get_socket(host_ip, base_module)
dht_client.send_put(s, dht_client.dht_key, value)
s.close()
s = dht_client.get_socket(host_ip, base_module)
dht_client.send_get(s, dht_client.dht_key)
s.close()
close_all_peers()


print("\nTEST 3 | Create network with 5 peers without certificate validation")
start_network(5)
time.sleep(10)
close_all_peers()


print("\nTEST 4 | Create network with 5 peers with certificate validation enforced. Bug \"SSL routines::certificate verify failed\".")
verify_peer_before = verify_peer
verify_peer = True
start_network(5)
time.sleep(10)
close_all_peers()
verify_peer = verify_peer_before


print("\nTest 5 | Update peer in Routingtable after another takes their IP & Port")
start_network(3)
close_peer(2)
close_peer(1)
#Now peer 0 has two dead nodes in it's routingtable

#Restart peer 1:
#This will try to contact the dead node 3 and should handle it accordingly
start_peer_container(get_ip_for_index(1), 1)

#Restart peer 2:
#Now node 2 should replace the old  node 3 with the new node 3 and nobody should have any old peers left
start_peer_container(get_ip_for_index(2), 2)
#TODO @Marius, maybe print which statement to look for if the test is successful
close_all_peers()


#TODO @Marius, revise prints errors
print("\nTEST 6 | Random node access for set and get operations")
start_network(5)
time.sleep(2)
random_node_ip = f"{ip_prefix}0.{random.randint(2, 6)}"
s = dht_client.get_socket(random_node_ip, base_module)
bytes("42 ist eine sehr tolle Zahl", encoding='utf=8')
dht_client.send_put(s, dht_client.dht_key, value)
s.close()
s = dht_client.get_socket(random_node_ip, base_module)
dht_client.send_get(s, dht_client.dht_key)
s.close()
close_all_peers()

print("\nTEST 7 | Stress test with 50 nodes and heavy traffic")
start_network(50)
time.sleep(5)

random_keys = []

for key in range(0,20):
    random_keys.append(bytes(random_string(), encoding='utf=8'))

for key in range(20):
    s = dht_client.get_socket(host_ip, base_module)
    dht_client.send_put(s, random_keys[key], bytes(random_string(), encoding='utf-8'))
    s.close()

print("--------RESPONSES--------")
for key in random_keys:
    s = dht_client.get_socket(host_ip, base_module)
    dht_client.send_get(s, key)
    s.close()

close_all_peers()