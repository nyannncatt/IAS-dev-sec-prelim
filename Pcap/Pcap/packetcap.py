import pyshark
import csv
import time
import datetime

# Mapping of flag values to their meanings
TCP_FLAG_MAPPING = {
    '0x0010': 'OTH',
    '0x0018': 'REJ',
    '0x0012': 'RSTO',
    '0x0014': 'RSTOS0',
    '0x0014': 'RSTR',
    '0x0002': 'S0',
    '0x0004': 'S1',
    '0x0006': 'S2',
    '0x0008': 'S3',
    '0x0010': 'SF',
    '0x0018': 'SH',
    '0x0011': 'SF'
}

# Function to convert timestamp to hh:mm:ss AM/PM format
def format_timestamp(timestamp):
    # Convert timestamp to datetime object
    dt_object = datetime.datetime.fromtimestamp(timestamp)
    # Format datetime object as hh:mm:ss AM/PM
    formatted_time = dt_object.strftime("%I:%M:%S %p")
    return formatted_time

# Function to capture network packets and extract features
def capture_and_extract_features(output_file, timestamp_file):
    # Create a CSV file and write header
    with open(output_file, 'w', newline='') as csvfile, open(timestamp_file, 'w') as timefile:
        fieldnames = ['duration', 'protocol_type','flag', 
                      'src_bytes', 'dst_bytes', 'logged_in', 'srv_count', 'dst_host_count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # Capture packets on the desired interface (e.g., 'Wi-Fi')
        capture = pyshark.LiveCapture(interface='Wi-Fi', display_filter='tcp or udp')

        # Initialize a dictionary to store start times for each IP address
        ip_packets = {}

        # Iterate over each packet
        for packet in capture.sniff_continuously():
            if 'IP' in packet:
                ip_address = packet.ip.src

                # Extract relevant features
                if ip_address not in ip_packets:
                    ip_packets[ip_address] = True  # Store only one packet per IP
                    start_time = time.time()  # Start time for the packet

                    # Format the timestamp
                    formatted_time = format_timestamp(start_time)

                    # Write the formatted timestamp to the time file
                    timefile.write(f"{formatted_time}\n")
                    timefile.flush()  # Flush buffer to ensure immediate writing

                    if 'TCP' in packet:
                        protocol_type = 'tcp'
                        flag = packet.tcp.flags
                        src_port = packet.tcp.srcport
                        dst_port = packet.tcp.dstport
                    elif 'UDP' in packet:
                        protocol_type = 'udp'
                        flag = 'SF'  # No flags for UDP packets
                        src_port = packet.udp.srcport
                        dst_port = packet.udp.dstport

                    # Map flag value to its meaning (for TCP packets)
                    flag_meaning = TCP_FLAG_MAPPING.get(flag, flag) if flag else None

                    # Write the extracted features to the CSV file
                    writer.writerow({
                        'duration': time.time() - start_time,
                        'protocol_type': protocol_type,
                        'flag': flag_meaning,
                        'src_bytes': packet.tcp.len if 'TCP' in packet else packet.udp.length,
                        'dst_bytes': packet.ip.len,
                        'logged_in': 'ACK' in packet.tcp.flags if 'TCP' in packet else None,
                        'srv_count': src_port,
                        'dst_host_count': dst_port
                    })
                    csvfile.flush()  # Flush buffer to ensure immediate writing

# Specify the output file paths
output_file = 'captured_packets.csv'
timestamp_file = 'packet_timestamps.txt'

# Call the function to capture packets and extract features
while(True):
    capture_and_extract_features(output_file, timestamp_file)
    time.sleep(60)