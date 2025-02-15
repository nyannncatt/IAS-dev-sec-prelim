import subprocess
import schedule
import time

# Function to add iptables rule to block IP
def block_ip(ip):
    subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name", f"Block {ip}", "dir", "in", "action", "block", "remoteip", ip])
    print(f"Blocked IP: {ip}")

# Function to add iptables rule to block URL
def block_url(url):
    subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name", f"Block {url}", "dir", "out", "action", "block", "remoteip", url])
    print(f"Blocked URL: {url}")

# Read IPs from file and block them
def block_ips_from_file(ip_file):
    with open(ip_file, "r") as file:
        ips = file.readlines()
        for ip in ips:
            block_ip(ip.strip())

# Read URLs from file and block them
def block_urls_from_file(url_file):
    with open(url_file, "r") as file:
        urls = file.readlines()
        for url in urls:
            block_url(url.strip())
            
def block():
    ip_file = "suspicious_ips.txt"
    url_file = "suspicious_urls.txt"
    block_ips_from_file(ip_file)
    block_urls_from_file(url_file)
            
schedule.every(1).minutes.do(block)

# Infinite loop to keep the script running
while True:
    schedule.run_pending()
    time.sleep(1)  # Sleep for a short duration to avoid high CPU usage