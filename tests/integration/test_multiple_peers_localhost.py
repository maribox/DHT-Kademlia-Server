import os
import subprocess
import time
import socket
import threading
import random
import dht_client




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

def start_command(program_path, peer_id, peer_port=None):
    module_port = base_module + peer_id * 2
    p2p_port = base_module + peer_id * 2 + 1

    if peer_port:
        return f"{program_path} -a {host_ip} -m {module_port} -p {p2p_port} -A {host_ip} -P {peer_port} -l {loglevel}"
    else:
        return f"{program_path} -a {host_ip} -m {module_port} -p {p2p_port} -l {loglevel}"

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

def start_network(n_peers):
    command = start_command(program_path, 0)
    process = start(command, 0)
    opened_processes[0] = process
    time.sleep(0.5)
    for i in range(1, n_peers):
        command = start_command(program_path, i, base_module + 1)
        process = start(command, i)
        opened_processes[i] = process
        time.sleep(0.2)

def close_modules_randomly(number):
    to_close = min(number, len(opened_processes))
    for _ in range(to_close):
        peer_i, process = random.choice(opened_processes)
        process.terminate() 
        print(f"Closed peer {peer_i}")

def close_all_peers():
    for peer_i, process in opened_processes.items():
        process.terminate()
        print(f"Closed peer {peer_i}")
    
def close_peer(displayed_peer_no):
    if (displayed_peer_no in opened_processes):
        opened_processes[displayed_peer_no].terminate()
        print(f"Closed peer {displayed_peer_no}")

host_ip = get_local_ip()
print_lock = threading.Lock()
__dirname__ = os.path.dirname(__file__)
opened_processes = {}

print("----------------TESTING----------------")

#-------- PARAMETER --------#
base_module = 8000
program_path = f"{__dirname__}/../../cmake-build-debug/dht_server"
loglevel = "info" # can be trace|debug|info|warn|err|critical|off
#--------#--------#---------#


start_network(0)

print("\nTEST 1 | single node should return DHT_FAILURE if value is not saved\n")
s1 = dht_client.get_socket(host_ip, base_module)

dht_client.send_get(s1, dht_client.dht_key)

s1.close()

print("\nTEST 2 | single node should return DHT_SUCCESS if it was saved before (also persistent across connections)\n")

s2 = dht_client.get_socket(host_ip, base_module)
dht_client.send_put(s2, dht_client.dht_key, dht_client.dht_value)
s2.close()

s3 = dht_client.get_socket(host_ip, base_module)
dht_client.send_get(s3, dht_client.dht_key)
s3.close()
close_all_peers()
base_module += 2

print("TEST 3 | 5 peers connect to each other successfully and we can connect to them (inspect output, look for the following message:)\n'Network expansion finished! Successfully joined network.'")
start_network(5)
s1 = dht_client.get_socket(host_ip, base_module + 2)
s2 = dht_client.get_socket(host_ip, base_module + 4)
s3 = dht_client.get_socket(host_ip, base_module + 6)
s1.close()
s2.close()
s3.close()
close_all_peers()
base_module += 5*2

# feel free to also test in here if you want to run tests locally.
# This file has been abandoned in favor of the docker test

