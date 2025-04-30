import time
import platform
import sys
import logging
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, get_if_list, conf
from sklearn.neighbors import KNeighborsClassifier
import numpy as np
import pickle
from sklearn.preprocessing import MinMaxScaler

# Suppress Scapy warnings
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Detect operating system
OS = platform.system().lower()
print(f"Detected OS: {OS}")

# Setup logging
log_file = f"attack_log_{time.strftime('%Y%m%d_%H%M%S')}.txt"
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logging.info(f"Starting attack detection on {OS}")

# CICIDS2018 label to attack type mapping
ATTACK_TYPES = {
    0: "Benign",
    1: "Bot",
    2: "Brute Force - Web",
    3: "Brute Force - XSS",
    4: "DDoS - HOIC",
    5: "DDoS - LOIC-UDP",
    6: "DDoS - LOIC-HTTP",
    7: "DoS - GoldenEye",
    8: "DoS - Hulk",
    9: "DoS - SlowHTTPTest",
    10: "DoS - Slowloris",
    11: "FTP-BruteForce",
    12: "Infiltration (Enumeration/Port Scanning)",
    13: "SQL Injection",
    14: "SSH-Bruteforce"
}

# Define the 15 features expected by the KNN model (CICIDS2018)
FEATURE_NAMES = [
    'Flow IAT Mean', 'Fwd Packet Length Max', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Fwd IAT Mean', 'Fwd IAT Min', 'Init Fwd Win Bytes', 'Fwd Seg Size Min',
    'Bwd Packet Length Std', 'Bwd IAT Mean', 'Bwd IAT Min', 'Init Bwd Win Bytes',
    'Avg Fwd Segment Size', 'RST Flag Count', 'ECE Flag Count'
]

def get_network_interface():
    """Select a network interface with Windows debugging."""
    interfaces = get_if_list()
    if not interfaces:
        logging.error("No network interfaces found.")
        print("No network interfaces found. Exiting.")
        sys.exit(1)

    print("Available interfaces:", interfaces)

    if OS == 'linux':
        if 'enp0s3' in interfaces:  # Ubuntu VMs
            return 'enp0s3'
        elif 'eth0' in interfaces:  # Kali/older Linux
            return 'eth0'
        else:
            return interfaces[0]  # Fallback
    elif OS == 'windows':
        # Windows requires \Device\NPF_ prefix for GUIDs
        for iface in interfaces:
            if '{' in iface:  # GUID format
                # Prepend Npcap prefix if not already present
                if not iface.startswith('\\Device\\NPF_'):
                    iface = f"\\Device\\NPF_{iface}"
                return iface
        # Fallback: Prompt user to select
        print("Could not auto-select a valid Windows interface.")
        print("Please select an interface from the list above (e.g., \\Device\\NPF_{GUID}):")
        selected = input("Enter interface: ").strip()
        return selected if selected else interfaces[0]
    else:
        logging.error(f"Unsupported OS: {OS}")
        print(f"Unsupported OS: {OS}. Exiting.")
        sys.exit(1)

def load_knn_model():
    """Load the pre-trained KNN model."""
    try:
        with open('knn_model.pkl', 'rb') as f:
            model = pickle.load(f)
        logging.info("KNN model loaded successfully.")
        return model
    except FileNotFoundError:
        logging.error("knn_model.pkl not found.")
        print("knn_model.pkl not found. Ensure it’s in the current directory.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error loading KNN model: {e}")
        print(f"Error loading KNN model: {e}")
        sys.exit(1)

def extract_features_from_flow(packets):
    """Extract the 15 CICIDS2018 features and additional flow metrics."""
    if not packets:
        return [0] * 15, 0, "Unknown"

    times = [p['time'] for p in packets]
    lengths = [p['len'] for p in packets]
    flags = [p['flags'] for p in packets]
    wins = [p['win'] for p in packets]
    iat = np.diff(times) if len(times) > 1 else [0]
    duration = max(times) - min(times) if len(times) > 1 else 0
    pkt_rate = len(packets) / duration if duration > 0 else 0
    proto = "TCP" if packets[0]['proto'] == 6 else "UDP" if packets[0]['proto'] == 17 else "Other"

    features = [
        np.mean(iat) if iat.size > 0 else 0,  # Flow IAT Mean
        max(lengths),                         # Fwd Packet Length Max
        np.mean(lengths),                     # Fwd Packet Length Mean
        np.std(lengths),                      # Fwd Packet Length Std
        np.mean(iat) if iat.size > 0 else 0,  # Fwd IAT Mean
        min(iat) if iat.size > 0 else 0,     # Fwd IAT Min
        wins[0] if wins else 0,               # Init Fwd Win Bytes
        min(lengths),                         # Fwd Seg Size Min
        np.std(lengths),                      # Bwd Packet Length Std (approx)
        np.mean(iat) if iat.size > 0 else 0,  # Bwd IAT Mean (approx)
        min(iat) if iat.size > 0 else 0,     # Bwd IAT Min (approx)
        wins[-1] if wins else 0,              # Init Bwd Win Bytes
        np.mean(lengths),                     # Avg Fwd Segment Size
        sum(1 for f in flags if 'R' in str(f)),  # RST Flag Count
        sum(1 for f in flags if 'E' in str(f))   # ECE Flag Count
    ]
    return features, pkt_rate, proto

def packet_callback(packet, knn, scaler, feature_buffer):
    """Process packets and detect attacks."""
    flows = packet_callback.flows

    if IP in packet and (TCP in packet or UDP in packet):
        flow_key = (packet[IP].src, packet[IP].dst,
                    packet[TCP].sport if TCP in packet else packet[UDP].sport,
                    packet[TCP].dport if TCP in packet else packet[UDP].dport,
                    packet[IP].proto)
        flows[flow_key].append({
            'time': time.time(),
            'len': len(packet),
            'flags': packet[TCP].flags if TCP in packet else 0,
            'win': packet[TCP].window if TCP in packet else 0,
            'proto': packet[IP].proto
        })

        total_packets = sum(len(packets) for packets in flows.values())
        if total_packets >= 100:
            X = []
            flow_keys = []
            pkt_rates = []
            protos = []

            for flow_key, packets in flows.items():
                features, pkt_rate, proto = extract_features_from_flow(packets)
                X.append(features)
                flow_keys.append(flow_key)
                pkt_rates.append(pkt_rate)
                protos.append(proto)

            X = np.array(X)

            if len(feature_buffer) < 1000:
                feature_buffer.extend(X)
                if len(feature_buffer) >= 1000:
                    scaler.fit(np.array(feature_buffer))
                    print("Scaler fitted with initial 1000 samples.")
                    logging.info("Scaler fitted with initial 1000 samples.")
            else:
                X_scaled = scaler.transform(X)
                predictions = knn.predict(X_scaled)
                probabilities = knn.predict_proba(X_scaled)

                attack_indices = np.where(predictions != 0)[0]
                if attack_indices.size > 0:
                    print(f"Detected {attack_indices.size} attacks in {total_packets} packets!")
                    logging.info(f"Detected {attack_indices.size} attacks in {total_packets} packets!")
                    for idx in attack_indices:
                        flow_key = flow_keys[idx]
                        attack_label = predictions[idx]
                        attack_type = ATTACK_TYPES.get(attack_label, "Unknown")
                        confidence = max(probabilities[idx]) * 100
                        pkt_rate = pkt_rates[idx]
                        proto = protos[idx]

                        msg = (f"Attack Type: {attack_type} (Label: {attack_label})\n"
                               f"Flow: src={flow_key[0]}:{flow_key[2]} -> dst={flow_key[1]}:{flow_key[3]}\n"
                               f"Protocol: {proto}\n"
                               f"Confidence: {confidence:.2f}%\n"
                               f"Packet Rate: {pkt_rate:.2f} packets/sec")
                        print(msg)
                        logging.info(msg)
                else:
                    print(f"No attacks detected in {total_packets} packets.")
                    logging.info(f"No attacks detected in {total_packets} packets.")

            flows.clear()

def main():
    """Initialize and start detection."""
    interface = get_network_interface()
    print(f"Using interface: {interface}")
    logging.info(f"Using interface: {interface}")

    knn = load_knn_model()
    scaler = MinMaxScaler(feature_range=(0, 1))
    feature_buffer = []

    # Configure Scapy for Windows with Npcap
    if OS == 'windows':
        conf.use_pcap = True
        print("Configured Scapy to use Npcap. Ensure it’s installed: https://nmap.org/npcap/")

    packet_callback.flows = defaultdict(list)
    print("Starting advanced attack detection with Scapy and KNN...")
    print("Collecting initial data to fit scaler (first 1000 samples)...")
    logging.info("Starting detection.")

    try:
        sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, knn, scaler, feature_buffer), store=0)
    except PermissionError:
        print("Permission denied. Run with elevated privileges (sudo on Linux, admin on Windows).")
        logging.error("Permission denied.")
        sys.exit(1)
    except Exception as e:
        print(f"Error during packet capture: {e}")
        logging.error(f"Error during packet capture: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()