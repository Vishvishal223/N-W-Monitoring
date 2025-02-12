import os
import time
import csv
import matplotlib.pyplot as plt
from ping3 import ping
from scapy.all import ARP, Ether, srp

# Configuration
DURATION = 30  
INTERVAL = 5  
LOG_FILE = "network_log.csv"

# Function to check network connectivity
def check_ping(host="8.8.8.8"):
    response_time = ping(host)
    if response_time:
        print(f"[✓] Network is UP. Response time: {response_time:.2f} ms")
        return response_time
    else:
        print("[X] Network is DOWN!")
        return None

# Function to scan active devices in the network
def scan_network(ip_range="Your device's IP Address"):
    print("\nScanning network for active devices...")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = [{"IP": received.psrc, "MAC": received.hwsrc} for sent, received in result]

    if devices:
        print("\nActive Devices in the Network:")
        for device in devices:
            print(f"IP: {device['IP']}, MAC: {device['MAC']}")
    else:
        print("No active devices found.")

# Function to log network response time and stop after a set duration
def log_network_performance(filename=LOG_FILE, duration=DURATION, interval=INTERVAL):
    print("\nLogging network performance...")

    start_time = time.time()  # Record the start time

    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Response Time (ms)"])

        response_times = []
        timestamps = []

        while time.time() - start_time < duration:
            response_time = check_ping()
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

            if response_time:
                writer.writerow([timestamp, response_time])
                response_times.append(response_time)
                timestamps.append(timestamp)

            time.sleep(interval)

    print(f"\n Execution stopped automatically after {duration} seconds.")
    return timestamps, response_times

# Function to visualize network performance
def plot_network_performance(timestamps, response_times):
    if not response_times:
        print("No response times recorded. Skipping visualization.")
        return
    
    plt.figure(figsize=(10, 5))
    plt.plot(timestamps, response_times, marker='o', linestyle='-', color='b')
    plt.xlabel("Timestamp")
    plt.ylabel("Response Time (ms)")
    plt.title("Network Performance Over Time")
    plt.xticks(rotation=45)
    plt.grid()
    plt.show()

# Main function
if __name__ == "__main__":
    scan_network()
    timestamps, response_times = log_network_performance()
    plot_network_performance(timestamps, response_times)
