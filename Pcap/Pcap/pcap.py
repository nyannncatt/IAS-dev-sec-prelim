import pyshark
import time

# Function to capture packets and extract URIs and IP addresses
def capture_and_extract_uris():
    # Define the interface to capture packets on
    interface = 'Wi-Fi'  # Change this to your desired interface

    # Define the path to save the extracted URIs and IP addresses
    uri_output_file = f'extracted_uris.txt'
    ip_output_file = f'extracted_ip_addresses.txt'

    # Start capturing packets
    capture = pyshark.LiveCapture(interface=interface, bpf_filter='tcp port 80 or tcp port 443')

    # Define the URL to exclude
    excluded_url = 'http://www.msftconnecttest.com/connecttest.txt'
    excluded_ip = '172.17.176.56'
    unique_ips = set()

    # Define a function to extract URIs and IP addresses from HTTP packets
    def extract_uris_and_ip(packet):
        if hasattr(packet, 'http') and hasattr(packet.http, 'request_full_uri'):
            uri = packet.http.request_full_uri
            if uri and uri != excluded_url:  # Check if URI is not the excluded URL
                with open(uri_output_file, 'a') as f:
                    f.write(uri + '\n')

        if hasattr(packet, 'ip') and hasattr(packet.ip, 'dst'):
            dst_ip = packet.ip.dst
            if dst_ip != excluded_ip:
                if dst_ip not in unique_ips:
                    with open(ip_output_file, 'a') as f:
                        f.write(dst_ip + '\n')
                    unique_ips.add(dst_ip)

    # Apply the function to each captured packet
    capture.apply_on_packets(extract_uris_and_ip)

    print(f'URI and IP extraction complete. Results saved to {uri_output_file} and {ip_output_file}')

# Run the program continuously
while True:
    capture_and_extract_uris()
    time.sleep(60)  # Capture packets and extract URIs every minute
