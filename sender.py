# NOTE: scapy often requires root privileges to send packets.
# Run with: sudo python3 sender.py

import scapy
from scapy.all import IP, TCP, send, Raw 
import time
import random

# Define the target (using localhost for testing)
TARGET_IP = "127.0.0.1"
TARGET_PORT = 9000# Using a custom port to avoid system services
MALICIOUS_PAYLOADS = {
    r'<script>': "<script>alert('XSS');</script>",
    r'union\s+select': "union select * from users;--",
    r'\/etc\/passwd': "../../etc/passwd",
    r'bin\/sh': "/bin/sh -c 'echo vulnerable'",
    r'drop\s+table': "drop table users;",
    r'\bselect\b.*\bfrom\b': "select email, password from users",
    r'\binsert\b.*\binto\b': "insert into users (admin) values (true);--",
    r'\bdelete\b.*\bfrom\b': "delete from logs where id=1;--"
}


def send_normal_packet():
    """Send a normal packet to the target"""
    packet = IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT) / Raw(load="TEST_ID:1234 Hello, this is a normal packet!")
    send(packet, verbose=0)
    print("Sent a normal packet.")

def send_malicious_packet():
    """Send a randomly chosen malicious payload"""
    # Randomly select a pattern and its corresponding payload
    pattern, payload = random.choice(list(MALICIOUS_PAYLOADS.items()))
    full_payload = f"TEST_ID:1234 {payload}"
    
    packet = IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT) / Raw(load=full_payload)
    send(packet, verbose=0)
    print(f"Sent malicious payload: {pattern}")

def send_custom_packet(payload):
    """Send a packet with a custom payload"""
    packet = IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT) / Raw(load=f"TEST_ID:1234 {payload}")
    send(packet, verbose=0)
    print(f"Sent custom packet with payload: {payload}")

def send_packets(num_packets=10):
    """Send test packets - both normal and malicious"""
    print(f" Sending {num_packets} test packets...")

    for i in range(num_packets):
        # Simulate adaptive attacker that learns from defender's behavior
        if i > 5:
            # Reduce attack probability as detection system might have adapted
            attack_prob = 0.3
        else:
            attack_prob = 0.5

        # Use random.random() for probability check
        if random.random() < attack_prob:
            send_malicious_packet()
        else:
            send_normal_packet()

        time.sleep(0.5)

if __name__ == "__main__":
    # Ask user how many packets to send
    try:
        count = int(input("How many packets to send (default: 10)? ") or "10")
    except ValueError:
        count = 10

    print("\n*** Note: Sending raw packets usually requires root privileges. ***")
    print(f"*** If it fails, try running with: sudo python3 {__file__} ***\n")
    try:
        send_packets(count)
        print("\n Finished sending packets.")
    except PermissionError:
        print("\n Permission denied. Please run this script using sudo.")
    except Exception as e:
        print(f"\n An error occurred: {e}")
