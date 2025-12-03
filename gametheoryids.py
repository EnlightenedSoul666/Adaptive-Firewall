game_theory_ids.py

# NOTE: Requires root privileges for sniffing and iptables.
# Run with: sudo python3 game_theory_ids.py

import scapy
from scapy.all import sniff, TCP, Raw, IP  
from scapy.arch import get_if_list
import hashlib
import subprocess
import time
import secrets
import random
import math
from collections import defaultdict
import re
import csv
import json
import os

# Global variables and configurations
THRESHOLD = 0.7  # Attack probability threshold for blocking
ATTACK_PACKET_WINDOW = 8  # Track last 8 packets for decisions
ip_packet_count = defaultdict(int)  # Track packets per IP
ip_recent_actions = defaultdict(list)  # Track recent packet type
LOG_FILE = "attack_log.csv"
STATS_FILE = "stats.json"
attack_probabilities = defaultdict(lambda: 0.1)  # Bayesian probabilities
blocked_ips = set()  # Track blocked IPs

# Only process packets with this test identifier
TEST_IDENTIFIER = "TEST_ID:1234"

# Initialize dynamic patterns
dynamic_patterns = {
    r'<script>', 
    r'union\s+select',
    r'\/etc\/passwd',
    r'bin\/sh',
    r'drop\s+table',
    r'\bselect\b.*\bfrom\b',
    r'\binsert\b.*\binto\b',
    r'\bdelete\b.*\bfrom\b'
}

# Game theory payoff matrix
# Format: [defender_utility, attacker_utility]
PAYOFF_MATRIX = {
    ("block", "attack"): [4, -8],    # Reduced defender reward
    ("block", "normal"): [-2, -1],   # Higher false-block penalty
    ("allow", "attack"): [-6, 6],    # Reduced penalty for misses
    ("allow", "normal"): [2, 1]      # Higher allowance reward
}

# Game theory strategy probabilities (Defender starts neutral)
defender_strategy = {"block": 0.05, "allow": 0.95}
# Attacker strategy is learned per IP
attacker_strategy = defaultdict(lambda: {"attack": 0.5, "normal": 0.5})


def get_dynamic_threshold(ip):
    """Gradually lowers threshold after multiple packets"""
    base = 0.7
    packets_observed = ip_packet_count[ip]
    # After 5 packets, threshold drops by 0.04 per packet
    return max(0.4, base - (max(0, packets_observed-5) * 0.04))
    
    
# --- Initialization Functions ---
def initialize_log_file():
    if not os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["timestamp", "source_ip", "destination_ip", "payload", "probability", "action", "is_attack", "utility_defender", "utility_attacker"])
            print(f" Initialized log file: {LOG_FILE}")
        except PermissionError:
            print(f"  Permission denied creating log file: {LOG_FILE}. Check directory permissions.")
        except Exception as e:
            print(f"  Error initializing log file: {e}")

def initialize_stats_file():
    if not os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, "w") as file:
                json.dump({
                    "total_packets_processed": 0,
                    "detected_malicious_attempts": 0,  # Based on pattern match
                    "blocked_ips_count": 0,
                    "current_blocked_ips": [],
                    "cumulative_defender_utility": 0,
                    "cumulative_attacker_utility": 0,
                    "learned_patterns_count": len(dynamic_patterns)
                }, file, indent=4)
            print(f" Initialized stats file: {STATS_FILE}")
        except PermissionError:
            print(f"  Permission denied creating stats file: {STATS_FILE}. Check directory permissions.")
        except Exception as e:
            print(f"  Error initializing stats file: {e}")

# --- Core Logic Functions ---

def is_malicious(packet):
    """Check if a packet contains malicious payload, returning both status and payload"""
    payload = ""
    if packet.haslayer(Raw):
        try:
            # Correctly aligned under try
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            is_malicious_status = any(re.search(pattern, payload, re.I) for pattern in dynamic_patterns)
            return is_malicious_status, payload
        except Exception as e:
            print(f" Error processing payload: {e}")
            return False, ""
    return False, ""

def update_dynamic_patterns(payload):
    """Update pattern recognition using observed payloads"""
    global dynamic_patterns
    try:
        # Find potential tokens (alphanumeric words of 5+ characters)
        tokens = re.findall(r'\b[a-zA-Z0-9]{5,}\b', payload)
        new_patterns_found = 0
        for token in tokens:
            # Avoid adding common HTTP words or already known patterns
            if token.lower() not in ["http", "host", "user", "agent", "content", "type", "length"] and token not in dynamic_patterns:
                # Heuristic: Higher suspicion for more uppercase chars or random chance
                # Convert to float division
                token_suspicion = sum(1 for char in token if char.isupper()) / float(len(token)) if len(token) > 0 else 0

                # Add if suspicious or by random chance (exploration)
                if token_suspicion > 0.4 or secrets.randbelow(100) < 10:  # Adjusted thresholds
                    dynamic_patterns.add(token)
                    new_patterns_found += 1
                    print(f" Learned new potential pattern: {token}")

        if new_patterns_found > 0:
            update_stats({"learned_patterns_count": len(dynamic_patterns)})

    except Exception as e:
        print(f" Error during dynamic pattern update: {e}")

def update_attack_probability(ip, detected_attack):
    prior = max(0.01, attack_probabilities[ip])
    
    if detected_attack:
        # Smaller increment per detection
        posterior = min(0.99, prior * 1.25)
        # Track recent malicious actions
        ip_recent_actions[ip].append(1)
    else:
        # Faster decay for normal packets
        posterior = max(0.01, prior * 0.88)
        ip_recent_actions[ip].append(0)
    
    # Keep only last 8 actions
    ip_recent_actions[ip] = ip_recent_actions[ip][-ATTACK_PACKET_WINDOW:]
    
    # Adaptive learning rate based on consistency
    consistent_attacks = sum(ip_recent_actions[ip]) / len(ip_recent_actions[ip])
    alpha = 0.15 + (0.10 * consistent_attacks)  # Ranges 0.15-0.25
    
    attack_probabilities[ip] = prior + alpha * (posterior - prior)


def update_game_strategies(ip, detected_attack):
    """Update game theory strategies based on observed behavior and probabilities"""
    global defender_strategy  # Allow modification of global defender strategy

    # --- Update Attacker Strategy Estimation ---
    # More strongly adjust attacker model based on detection
    adjustment_rate = 0.15
    current_attacker_prob = attacker_strategy[ip]["attack"]

    if detected_attack:
        new_attacker_prob = min(1.0, current_attacker_prob + adjustment_rate * (1.0 - current_attacker_prob))
    else:
        new_attacker_prob = max(0.0, current_attacker_prob - adjustment_rate * current_attacker_prob)

    attacker_strategy[ip]["attack"] = new_attacker_prob
    attacker_strategy[ip]["normal"] = 1.0 - new_attacker_prob

    # --- Update Defender Strategy ---
    # Calculate expected utility for defender's pure strategies (Block vs Allow)
    # based on the *estimated* attacker strategy for this IP
    eu_block = (attacker_strategy[ip]["attack"] * PAYOFF_MATRIX[("block", "attack")][0] +
                attacker_strategy[ip]["normal"] * PAYOFF_MATRIX[("block", "normal")][0])

    eu_allow = (attacker_strategy[ip]["attack"] * PAYOFF_MATRIX[("allow", "attack")][0] +
                attacker_strategy[ip]["normal"] * PAYOFF_MATRIX[("allow", "normal")][0])

    # Simple approach: Lean towards the action with higher expected utility
    # More sophisticated: Could use Nash equilibrium calculation if attacker model was more complex
    utility_diff = eu_block - eu_allow

    # Adjust defender's mixed strategy probability (logistic function or similar)
    # This adjusts the *general* defender tendency based on recent interactions with *this* IP
    # Lambda controls sensitivity of adjustment
    lambda_sensitivity = 0.1
    delta_block_prob = lambda_sensitivity * (1 / (1 + math.exp(-utility_diff))) - defender_strategy["block"] * lambda_sensitivity

    defender_strategy["block"] = max(0.01, min(0.99, defender_strategy["block"] + delta_block_prob))
    defender_strategy["allow"] = 1.0 - defender_strategy["block"]

def make_persistent_block_decision(ip):
    ip_packet_count[ip] += 1
    
    # Calculate dynamic threshold
    dynamic_threshold = get_dynamic_threshold(ip)
    current_prob = attack_probabilities[ip]
    
    # Only block if:
    # 1. Probability exceeds dynamic threshold
    # 2. Minimum 5 packets observed
    # 3. At least 30% of recent packets were malicious
    recent_malicious_ratio = sum(ip_recent_actions[ip]) / len(ip_recent_actions[ip]) if ip_recent_actions[ip] else 0
    
    if (current_prob > dynamic_threshold and 
        ip_packet_count[ip] >= 5 and 
        recent_malicious_ratio >= 0.3):
        
        print(f" Gradual Block Triggered for {ip}:")
        print(f"   - Suspicion: {current_prob:.2f} > Threshold: {dynamic_threshold:.2f}")
        print(f"   - Packets: {ip_packet_count[ip]}, Malicious Ratio: {recent_malicious_ratio:.0%}")
        
        block_ip(ip)
    else:
        print(f" Monitoring {ip}: P={current_prob:.2f} (Threshold: {dynamic_threshold:.2f}), "
              f"Packets: {ip_packet_count[ip]}, Recent Attacks: {sum(ip_recent_actions[ip])}/{len(ip_recent_actions[ip])}")

def block_ip(ip):
    """Block IP address using iptables"""
    if ip in blocked_ips:
        return

    print(f" High threat from {ip} (P={attack_probabilities[ip]:.2f}). Attempting to block.")
    try:
        # Use insert (-I) instead of append (-A) to prioritize the block rule
        result = subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=True, capture_output=True, text=True)
        blocked_ips.add(ip)
        print(f" Blocked IP: {ip}")

        # Update Stats
        stats_update = {
            "blocked_ips_count": len(blocked_ips),
            "current_blocked_ips": list(blocked_ips),
            # Attributing utility for the *decision* to block
            "cumulative_defender_utility": PAYOFF_MATRIX[("block", "attack")][0] if attacker_strategy[ip]["attack"] > 0.5 else PAYOFF_MATRIX[("block", "normal")][0],
            "cumulative_attacker_utility": PAYOFF_MATRIX[("block", "attack")][1] if attacker_strategy[ip]["attack"] > 0.5 else PAYOFF_MATRIX[("block", "normal")][1]
        }
        update_stats(stats_update, increment=True)

    except FileNotFoundError:
        print("  Error: 'sudo' or 'iptables' command not found. Make sure iptables is installed and reachable.")
    except subprocess.CalledProcessError as e:
        print(f" Failed to block IP {ip} using iptables: {e}")
        print(f"   Stderr: {e.stderr}")
        print(f"   Stdout: {e.stdout}")
        print("   Ensure you are running the script with sudo privileges.")
    except Exception as e:
        print(f" An unexpected error occurred during IP blocking: {e}")

def log_event(packet, is_attack, probability, action, defender_utility, attacker_utility):
    """Log packet details and game outcome to CSV file"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    payload = packet[Raw].load.decode(errors='ignore') if packet.haslayer(Raw) else ""

    try:
        with open(LOG_FILE, "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, src_ip, dst_ip, payload[:100], f"{probability:.3f}", action, is_attack, defender_utility, attacker_utility])  # Log truncated payload
    except PermissionError:
        # Avoid crashing the main loop if logging fails
        print(f" Permission denied writing to log file: {LOG_FILE}. Log entry lost.")
    except Exception as e:
        print(f" Error writing to log file: {e}. Log entry lost.")

def update_stats(data_to_update, increment=False):
    """Update statistics in the JSON file"""
    try:
        # Read current stats
        with open(STATS_FILE, "r") as file:
            stats = json.load(file)

        # Update stats
        for key, value in data_to_update.items():
            if increment and key in stats:
                stats[key] = stats.get(key, 0) + value
            else:
                stats[key] = value

        # Write updated stats back
        with open(STATS_FILE, "w") as file:
            json.dump(stats, file, indent=4)

    except FileNotFoundError:
        print(f" Stats file {STATS_FILE} not found. Cannot update stats.")
        initialize_stats_file()  # Try to re-initialize
    except json.JSONDecodeError:
        print(f" Error decoding JSON from stats file {STATS_FILE}. Stats may be corrupted.")
        # Consider backing up corrupted file and re-initializing
    except PermissionError:
        print(f" Permission denied writing to stats file: {STATS_FILE}. Stats update lost.")
    except Exception as e:
        print(f" Error updating stats file: {e}. Stats update lost.")

# --- Packet Processing Callback ---

def packet_callback(packet):
    """Process incoming packets without duplicate checking"""
    # Basic packet validity checks
    if not packet.haslayer(IP) or not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return
        
    # Check for our test ID to filter out unrelated packets
    try:
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if TEST_IDENTIFIER not in payload:
            return  # Skip packets without our identifier
    except Exception:
        return  # Skip if payload check fails

    src_ip = packet[IP].src

    # Skip if IP is already blocked
    if src_ip in blocked_ips:
        return

    update_stats({"total_packets_processed": 1}, increment=True)

    # Analyze Packet
    is_potential_attack, payload = is_malicious(packet)

    # Update Dynamic Patterns
    if packet.haslayer(Raw):
        update_dynamic_patterns(payload)

    # Update Probabilities and Strategies
    update_attack_probability(src_ip, is_potential_attack)
    update_game_strategies(src_ip, is_potential_attack)

    # Decide Action
    chosen_action = "block" if random.random() < defender_strategy["block"] else "allow"

    # Determine Outcome & Log
    attacker_likely_action = "attack" if attacker_strategy[src_ip]["attack"] > 0.5 else "normal"
    payoffs = PAYOFF_MATRIX.get((chosen_action, attacker_likely_action), [0, 0])
    
    log_event(packet, is_potential_attack, attack_probabilities[src_ip], 
             chosen_action, payoffs[0], payoffs[1])

    if is_potential_attack:
        update_stats({"detected_malicious_attempts": 1}, increment=True)
        print(f" Attack detected from {src_ip}. Action: {chosen_action}. Probability: {attack_probabilities[src_ip]:.2f}")

    # Final blocking decision
    make_persistent_block_decision(src_ip)
# --- Main Execution ---

def perform_system_checks():
    """Perform system checks before starting IDS"""
    print(" Running system checks...")
    
    # 1. Verify interfaces
    try:
        if "lo" not in get_if_list():
            print(" Loopback interface not found!")
            print("Try: sudo ip link set lo up")
            return False
    except Exception as e:
        print(f" Interface check failed: {str(e)}")
        return False
        
    # 2. Verify packet capture
    try:
        test_sniff = sniff(iface="lo", count=1, timeout=2)
        if not test_sniff:
            print(" No packets captured on lo in test mode!")
            # Continue anyway, as this might be due to no traffic during the test
    except Exception as e:
        print(f" Packet capture test failed: {str(e)}")
        print("This might be due to insufficient permissions or no traffic during the test")
        # Continue anyway, as this might be a false alarm
    
    return True

def start_sniffing(interface="lo", filter_str="tcp port 9000"):  # Changed to TCP and specific port
    print(f" Starting packet sniffing on {interface} with filter: {filter_str}")
    try:
        # Configure Scapy
        from scapy.config import conf
        conf.use_pcap = True
        conf.iface = interface
        
        # Verify interface
        if interface not in get_if_list():
            raise ValueError(f"Interface {interface} not found")
            
        # Start sniffing with error handling
        sniff(
            iface=interface,
            filter=filter_str,
            prn=packet_callback,
            store=0
        )
    except KeyboardInterrupt:
        print("\n Ctrl+C detected. Stopping IDS...")
    except Exception as e:
        print(f" Sniffing failed: {str(e)}")
        print("Troubleshooting steps:")
        print(f"1. Verify interface exists: ip link show {interface}")
        print(f"2. Test raw capture: sudo tcpdump -i {interface} -nn -c 5 '{filter_str}'")
        print("3. Check if another program is using the network interface")

if __name__ == "__main__":
    print(" Initializing Game Theory IDS...")
    initialize_log_file()
    initialize_stats_file()

    print("\n*** Note: Packet sniffing and iptables require root privileges. ***")
    if os.geteuid() != 0:
        print(" Warning: Script not running as root. Sniffing and blocking may fail.")
        # Exit or continue based on desired behavior
        # exit("Please run this script using sudo.")

    # --- Configuration ---
    # Using loopback for testing with sender.py on same machine
    iface_to_sniff = "lo"
    # Using TCP on port 9000 to filter out unrelated traffic
    packet_filter = "tcp port 9000"

    # Perform system checks
    if not perform_system_checks():
        print(" System checks failed. Continuing anyway, but expect issues.")

    try:
        start_sniffing(interface=iface_to_sniff, filter_str=packet_filter)
    except KeyboardInterrupt:
        print("\n Ctrl+C detected. Stopping IDS...")
    except Exception as e:
        print(f"\n An unexpected error occurred in the main loop: {e}")
    finally:
        print("Final Stats:")
        try:
            with open(STATS_FILE, "r") as f:
                print(json.dumps(json.load(f), indent=4))
        except Exception as e:
            print(f"   Could not read stats file: {e}")
        print(" Exiting.")
