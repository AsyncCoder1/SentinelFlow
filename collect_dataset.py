from scapy.all import sniff, IP, TCP
import csv
import os
import random
import subprocess
import threading
import time


SERVER_IP = "172.20.0.3"
INTERFACE = "br-bff3fb989aae"
SERVER_PORT = 8000

# V2 dataset - keeps the original V1 dataset untouched
DATASET_FILE = "traffic_dataset_v2.csv"

TARGET_NORMAL = 500
TARGET_ANOMALY = 500

CAPTURE_TIME = 5


# ========================================
# TRAFFIC STATISTICS
# ========================================

stats = {
    "packets": 0,
    "bytes": 0,
    "connections": 0,
    "http_requests": 0,
    "packet_sizes": []
}


def reset_stats():

    stats["packets"] = 0
    stats["bytes"] = 0
    stats["connections"] = 0
    stats["http_requests"] = 0
    stats["packet_sizes"] = []


# ========================================
# PACKET HANDLER
# ========================================

def packet_handler(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    # Only monitor client -> server traffic
    if source_ip == SERVER_IP:
        return

    if destination_ip != SERVER_IP:
        return

    # --------------------------------
    # BASIC PACKET FEATURES
    # --------------------------------

    stats["packets"] += 1
    stats["bytes"] += len(packet)

    # Record packet size
    stats["packet_sizes"].append(len(packet))

    # --------------------------------
    # TCP FEATURES
    # --------------------------------

    if TCP in packet:

        flags = int(packet[TCP].flags)

        # SYN without ACK = new TCP connection
        if flags & 0x02 and not flags & 0x10:
            stats["connections"] += 1

        # --------------------------------
        # HTTP REQUEST DETECTION
        # --------------------------------

        if packet[TCP].payload:

            payload = bytes(packet[TCP].payload)

            methods = (
                b"GET ",
                b"POST ",
                b"PUT ",
                b"DELETE ",
                b"PATCH "
            )

            if payload.startswith(methods):
                stats["http_requests"] += 1


# ========================================
# GENERATE TRAFFIC
# ========================================

def send_requests(request_count, delay):

    python_code = f"""
import urllib.request
import time

for i in range({request_count}):

    try:
        urllib.request.urlopen(
            'http://{SERVER_IP}:{SERVER_PORT}',
            timeout=2
        ).read()

    except Exception:
        pass

    time.sleep({delay})
"""

    subprocess.run(
        [
            "docker",
            "exec",
            "sentinel-client",
            "python",
            "-c",
            python_code
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


# ========================================
# CAPTURE ONE SAMPLE
# ========================================

def capture_sample(label):

    reset_stats()

    # ====================================
    # NORMAL TRAFFIC
    # ====================================

    if label == 0:

        normal_patterns = [
            (5, 0.50),
            (10, 0.30),
            (20, 0.20),
            (30, 0.10),
            (40, 0.08),
            (50, 0.05),
            (70, 0.03)
        ]

        request_count, delay = random.choice(
            normal_patterns
        )

    # ====================================
    # ANOMALOUS TRAFFIC
    # ====================================

    else:

        anomaly_patterns = [
            (60, 0.03),
            (80, 0.02),
            (100, 0.01),
            (150, 0.008),
            (200, 0.005),
            (300, 0.003),
            (500, 0.001)
        ]

        request_count, delay = random.choice(
            anomaly_patterns
        )

    print(
        f"Generating traffic: "
        f"{request_count} requests"
    )

    # ====================================
    # START PACKET CAPTURE
    # ====================================

    capture_thread = threading.Thread(
        target=lambda: sniff(
            iface=INTERFACE,
            timeout=CAPTURE_TIME,
            prn=packet_handler,
            store=False
        )
    )

    capture_thread.start()

    # Give Scapy time to start
    time.sleep(0.2)

    # ====================================
    # GENERATE TRAFFIC
    # ====================================

    send_requests(
        request_count,
        delay
    )

    # Wait until capture finishes
    capture_thread.join()

    duration = CAPTURE_TIME

    # ====================================
    # RATE FEATURES
    # ====================================

    packets_per_sec = (
        stats["packets"] / duration
    )

    bytes_per_sec = (
        stats["bytes"] / duration
    )

    connections_per_sec = (
        stats["connections"] / duration
    )

    http_requests_per_sec = (
        stats["http_requests"] / duration
    )

    # ====================================
    # PACKET SIZE FEATURES
    # ====================================

    if stats["packet_sizes"]:

        # Average packet size
        avg_packet_size = (
            sum(stats["packet_sizes"])
            / len(stats["packet_sizes"])
        )

        # Smallest packet
        min_packet_size = min(
            stats["packet_sizes"]
        )

        # Largest packet
        max_packet_size = max(
            stats["packet_sizes"]
        )

        # Standard deviation
        mean = avg_packet_size

        variance = sum(
            (size - mean) ** 2
            for size in stats["packet_sizes"]
        ) / len(stats["packet_sizes"])

        packet_size_std = variance ** 0.5

    else:

        avg_packet_size = 0
        min_packet_size = 0
        max_packet_size = 0
        packet_size_std = 0

    # ====================================
    # RETURN SAMPLE
    # ====================================

    return [
        round(packets_per_sec, 2),
        round(bytes_per_sec, 2),
        round(connections_per_sec, 2),
        round(http_requests_per_sec, 2),
        round(avg_packet_size, 2),
        min_packet_size,
        max_packet_size,
        round(packet_size_std, 2),
        label
    ]


# ========================================
# COUNT EXISTING SAMPLES
# ========================================

def count_samples():

    normal = 0
    anomaly = 0

    if not os.path.exists(DATASET_FILE):
        return normal, anomaly

    with open(
        DATASET_FILE,
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            if row["label"] == "0":
                normal += 1

            elif row["label"] == "1":
                anomaly += 1

    return normal, anomaly


# ========================================
# SAVE SAMPLE
# ========================================

def save_sample(sample):

    file_exists = os.path.exists(
        DATASET_FILE
    )

    with open(
        DATASET_FILE,
        "a",
        newline=""
    ) as file:

        writer = csv.writer(file)

        if not file_exists:

            writer.writerow([
                "packets_per_sec",
                "bytes_per_sec",
                "connections_per_sec",
                "http_requests_per_sec",
                "avg_packet_size",
                "min_packet_size",
                "max_packet_size",
                "packet_size_std",
                "label"
            ])

        writer.writerow(sample)


# ========================================
# COLLECT DATA
# ========================================

def collect(target, label, name):

    while True:

        normal, anomaly = count_samples()

        current = (
            normal
            if label == 0
            else anomaly
        )

        if current >= target:
            break

        print()
        print(
            f"{name}: "
            f"{current}/{target}"
        )

        sample = capture_sample(
            label
        )

        save_sample(sample)

        print(
            f"Saved sample: "
            f"packets/sec={sample[0]}, "
            f"bytes/sec={sample[1]}, "
            f"connections/sec={sample[2]}, "
            f"http/sec={sample[3]}, "
            f"avg_size={sample[4]}, "
            f"min_size={sample[5]}, "
            f"max_size={sample[6]}, "
            f"std_size={sample[7]}, "
            f"label={sample[8]}"
        )

        time.sleep(0.2)


# ========================================
# MAIN PROGRAM
# ========================================

print()
print("========================================")
print(" SentinelFlow ML Dataset Generator V2")
print("========================================")

normal, anomaly = count_samples()

print(
    "Existing NORMAL:",
    normal
)

print(
    "Existing ANOMALY:",
    anomaly
)

# ========================================
# COLLECT NORMAL DATA
# ========================================

print()
print("Collecting NORMAL traffic...")
print()

collect(
    TARGET_NORMAL,
    0,
    "NORMAL"
)

print()
print("========================================")
print(" NORMAL DATA COMPLETE")
print("========================================")

# ========================================
# COLLECT ANOMALY DATA
# ========================================

print()
print("Collecting ANOMALOUS traffic...")
print()

collect(
    TARGET_ANOMALY,
    1,
    "ANOMALY"
)

# ========================================
# FINAL RESULT
# ========================================

normal, anomaly = count_samples()

print()
print("========================================")
print(" DATASET V2 COMPLETE")
print("========================================")

print(
    "NORMAL:",
    normal
)

print(
    "ANOMALY:",
    anomaly
)

print(
    "TOTAL:",
    normal + anomaly
)

print()
print(
    "Dataset:",
    DATASET_FILE
)