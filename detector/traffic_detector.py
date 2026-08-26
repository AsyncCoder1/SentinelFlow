from pathlib import Path
import statistics
import threading
import time

import joblib
import pandas as pd
from scapy.all import IP, TCP, sniff


SERVER_IP = "172.20.0.3"
INTERFACE = "br-bff3fb989aae"
WINDOW_SECONDS = 2
MODEL_FILE = "sentinelflow_v2_model.joblib"

FEATURE_NAMES = [
    "packets_per_sec", "bytes_per_sec", "connections_per_sec",
    "http_requests_per_sec", "avg_packet_size", "min_packet_size",
    "max_packet_size", "packet_size_std",
]

model = joblib.load(Path(__file__).resolve().parent.parent / MODEL_FILE)
stats = {"packets": 0, "bytes": 0, "connections": 0, "http_requests": 0}
packet_sizes = []
observed_clients = set()
stats_lock = threading.Lock()
service_lock = threading.Lock()
capture_thread = None
analysis_thread = None
stop_event = threading.Event()
latest_result_lock = threading.Lock()
latest_result = {
    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    "status": "NO TRAFFIC", "prediction": None,
    "normal_probability": None, "anomaly_probability": None,
    "features": None,
}


def reset_stats():
    with stats_lock:
        for name in stats:
            stats[name] = 0
        packet_sizes.clear()
        observed_clients.clear()


def packet_handler(packet):
    if IP not in packet or packet[IP].dst != SERVER_IP:
        return
    with stats_lock:
        observed_clients.add(packet[IP].src)
        stats["packets"] += 1
        stats["bytes"] += len(packet)
        packet_sizes.append(len(packet))
        if TCP not in packet:
            return
        flags = int(packet[TCP].flags)
        if flags & 0x02 and not flags & 0x10:
            stats["connections"] += 1
        if packet[TCP].payload:
            payload = bytes(packet[TCP].payload)
            if payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ")):
                stats["http_requests"] += 1


def _take_window():
    with stats_lock:
        window_stats = stats.copy()
        window_sizes = packet_sizes.copy()
        window_clients = sorted(observed_clients)
        for name in stats:
            stats[name] = 0
        packet_sizes.clear()
        observed_clients.clear()
    return window_stats, window_sizes, window_clients


def calculate_features(window_stats=None, window_sizes=None):
    if window_stats is None or window_sizes is None:
        window_stats, window_sizes, _ = _take_window()
    features = {
        "packets_per_sec": window_stats["packets"] / WINDOW_SECONDS,
        "bytes_per_sec": window_stats["bytes"] / WINDOW_SECONDS,
        "connections_per_sec": window_stats["connections"] / WINDOW_SECONDS,
        "http_requests_per_sec": window_stats["http_requests"] / WINDOW_SECONDS,
        "avg_packet_size": 0, "min_packet_size": 0,
        "max_packet_size": 0, "packet_size_std": 0,
    }
    if window_sizes:
        features["avg_packet_size"] = sum(window_sizes) / len(window_sizes)
        features["min_packet_size"] = min(window_sizes)
        features["max_packet_size"] = max(window_sizes)
        if len(window_sizes) > 1:
            features["packet_size_std"] = statistics.stdev(window_sizes)
    return {name: round(features[name], 2) for name in FEATURE_NAMES}


def _predict(features):
    data = pd.DataFrame([[features[name] for name in FEATURE_NAMES]], columns=FEATURE_NAMES)
    prediction = int(model.predict(data)[0])
    probabilities = model.predict_proba(data)[0]
    return {
        "prediction": prediction,
        "status": "NORMAL" if prediction == 0 else "ANOMALY",
        "normal_probability": round(float(probabilities[0]), 4),
        "anomaly_probability": round(float(probabilities[1]), 4),
    }


def analyze_window(window_stats, window_sizes, window_clients=None):
    features = calculate_features(window_stats, window_sizes)
    result = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "NO TRAFFIC", "prediction": None,
        "normal_probability": None, "anomaly_probability": None,
        "features": features,
        "server_ip": SERVER_IP,
        "interface": INTERFACE,
        "client_ips": window_clients or [],
    }
    if window_stats["packets"]:
        result.update(_predict(features))
    return result


def _capture_packets():
    try:
        sniff(iface=INTERFACE, prn=packet_handler, store=False,
              stop_filter=lambda _: stop_event.is_set())
    except Exception as exc:
        print(f"Packet capture stopped: {exc}")


def _analyze_continuously():
    global latest_result
    while not stop_event.wait(WINDOW_SECONDS):
        result = analyze_window(*_take_window())
        with latest_result_lock:
            latest_result = result
        display_result(result)


def start_detector():
    global capture_thread, analysis_thread
    with service_lock:
        if capture_thread and capture_thread.is_alive():
            return
        stop_event.clear()
        capture_thread = threading.Thread(target=_capture_packets, name="sentinelflow-capture", daemon=True)
        analysis_thread = threading.Thread(target=_analyze_continuously, name="sentinelflow-analysis", daemon=True)
        capture_thread.start()
        analysis_thread.start()


def stop_detector():
    stop_event.set()


def get_latest_result():
    with latest_result_lock:
        return latest_result.copy()


def display_result(result):
    print("\n----------------------------------------")
    print("Traffic Window")
    print("----------------------------------------")
    print(f"Timestamp: {result['timestamp']}")
    print(f"Traffic Status: {result['status']}")
    if result["status"] != "NO TRAFFIC":
        for name in FEATURE_NAMES:
            print(f"{name.replace('_', ' ').title():22}: {result['features'][name]}")
        print(f"Prediction: {result['status']}")
        print(f"Normal probability : {result['normal_probability']:.2%}")
        print(f"Anomaly probability: {result['anomaly_probability']:.2%}")
        if result["status"] == "ANOMALY":
            print("!!! ALERT: ANOMALOUS TRAFFIC DETECTED !!!")


def run_detection():
    """Analyze the collected window without starting or stopping capture."""
    return analyze_window(*_take_window())


if __name__ == "__main__":
    print("========================================")
    print(" SENTINELFLOW REAL-TIME MONITOR")
    print("========================================")
    print(f"Interface : {INTERFACE}")
    print(f"Server IP : {SERVER_IP}")
    print(f"Window    : {WINDOW_SECONDS} seconds")
    print("Continuous packet capture: ACTIVE")
    start_detector()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_detector()
