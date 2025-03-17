import os
import platform
import subprocess

def isolate_threat(attacker_ip):
    print(f"⚠️ Isolating Threat from {attacker_ip}...")

    if platform.system() == "Windows":
        # Windows Firewall Rule to Block IP
        cmd = f'netsh advfirewall firewall add rule name="Block {attacker_ip}" dir=in action=block remoteip={attacker_ip}'
        try:
            subprocess.run(cmd, shell=True, check=True)
            print(f"✅ Blocked IP: {attacker_ip} using Windows Firewall")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to block {attacker_ip} on Windows")
    
    else:  # Linux/macOS
        cmd = f"sudo iptables -A INPUT -s {attacker_ip} -j DROP"
        os.system(cmd)
        print(f"✅ Blocked IP: {attacker_ip} using iptables")
def unblock_ips():
    """Unblock IPs only if no new attack in last 10 min."""
    current_time = time.time()
    for ip in list(ip_block_times.keys()):
        if current_time - ip_block_times[ip] > 600 and attack_count[ip] < 3:
            command = f'netsh advfirewall firewall delete rule name="Block {ip}"'
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                del ip_block_times[ip]
                blocked_ips.remove(ip)
                print(f"✅ Unblocked Safe IP: {ip}")
            else:
                print(f"❌ Failed to unblock {ip}. Error: {result.stderr}")
