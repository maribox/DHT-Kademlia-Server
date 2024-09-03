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

def start_dht_server_command(program_path, peer_id, peer_port=None):
    host_module_port = base_module_port + peer_id * 2
    host_p2p_port = base_p2p_port + peer_id * 2

    if peer_port:
        return f"{program_path} -a {host_ip} -m {host_module_port} -p {host_p2p_port} -A {host_ip} -P {peer_port}"
    else:
        return f"{program_path} -a {host_ip} -m {host_module_port} -p {host_p2p_port}"

def start(command, i):
    print(f"Starting peer {i + 1}: {first_start_command}")
    process = subprocess.Popen(
    command, 
    stdout=subprocess.PIPE, 
    stderr=subprocess.STDOUT, 
    shell=True
    )
    threading.Thread(target=stream_output, args=(process, f"Node {i + 1}", print_lock), daemon=True).start()



def stream_output(process, prefix, lock):
    for line in iter(process.stdout.readline, b''):
        if line:
            with lock:
                # Decode with errors='replace' to handle non-UTF-8 bytes gracefully
                print(f"{prefix}: {line.decode('utf-8', errors='replace').strip()}")

host_ip = get_local_ip()
base_module_port = 7401
base_p2p_port = 7404
n_peers = 0
program_path = "../../cmake-build-debug/dht_server"

# Create a lock to ensure only one process prints at a time
print_lock = threading.Lock()

#first_start_command = start_dht_server_command(program_path, 0)
#start(first_start_command, 0)
time.sleep(1)

for i in range(1, n_peers):
    start_command = start_dht_server_command(program_path, i, base_p2p_port)
    process = start(start_command, i)
    time.sleep(0.2)


print("----------------")
s = dht_client.get_socket(host_ip, base_module_port)
print("[+] Custom operation: Connected to server")
dht_client.send_put(s, dht_client.dht_key, dht_client.dht_value)
s = dht_client.get_socket(host_ip, base_module_port + 2)
time.sleep(1)
dht_client.send_get(s, dht_client.dht_key)
exit()
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
dht_client.send_get(s, dht_client.dht_key)
response = dht_client.send_get(s, dht_client.dht_key)
print(f"Get function {'successfully got' if response else 'did not get'} a valid response")

time.sleep(50)