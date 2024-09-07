import os
import subprocess
import time
import socket
import threading

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
        return f"{program_path} -a {host_ip} -m {module_port} -p {p2p_port} -A {host_ip} -P {peer_port}"
    else:
        return f"{program_path} -a {host_ip} -m {module_port} -p {p2p_port}"

def start(command, i, should_log_servers):
    print(f"Starting peer {i + 1}: {command}")
    if (should_log_servers):
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        threading.Thread(target=log_output, args=(process, f"Node {i + 1}", print_lock), daemon=True).start()
    else:
        process = subprocess.Popen(command, 
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)

def log_output(process, prefix, lock):
    for line in iter(process.stdout.readline, b''):
        if line:
            with lock:
                print(f"{prefix}: {line.decode('utf-8', errors='replace').strip()}")

def start_modules(should_log_servers):
    start(start_command(program_path, 0), 0, should_log_servers)
    time.sleep(1)

    for i in range(1, n_peers):
        command = start_command(program_path, i, base_module + 1)
        process = start(command, i, should_log_servers)
        time.sleep(0.2)
        
host_ip = get_local_ip()
print_lock = threading.Lock()
__dirname__ = os.path.dirname(__file__)




print("----------------TESTING----------------")

#-------- PARAMETER --------#
base_module = 7401
n_peers = 5
program_path = f"{__dirname__}/../../cmake-build-debug/dht_server"
should_log_servers = False
#--------#--------#---------#


start_modules(should_log_servers)

s1 = dht_client.get_socket(host_ip, base_module)
s2 = dht_client.get_socket(host_ip, base_module + 2)
s3 = dht_client.get_socket(host_ip, base_module + 4)
s4 = dht_client.get_socket(host_ip, base_module + 6)


dht_client.send_put(s1, dht_client.dht_key, dht_client.dht_value)
time.sleep(1)
dht_client.send_get(s3, dht_client.dht_key)
dht_client.send_get(s2, dht_client.dht_key)
dht_client.send_get(s1, dht_client.dht_key)

s1.close()
s2.close()
s3.close()
s4.close()
