import csv
import pandas as pd
import numpy as np
from scapy.all import *
import matplotlib.pyplot as plt

def analyze_protocol_hierarchy(pcap_file):
    packets = rdpcap(pcap_file)

    protocol_stats = {}
    total_packets = len(packets)

    for packet in packets:
        layers = packet.layers()
        protocol_hierarchy = []
        for layer in layers:
            protocol_hierarchy.append(layer.__name__)  # 将成员描述符转换为字符串
            protocol_path = " > ".join(protocol_hierarchy)

            if protocol_path in protocol_stats:
                protocol_stats[protocol_path]["Packets"] += 1
                protocol_stats[protocol_path]["Bytes"] += len(packet)
            else:
                protocol_stats[protocol_path] = {
                    "Packets": 1,
                    "Bytes": len(packet)
                }

    for protocol_path, stats in protocol_stats.items():
        stats["% Packets"] = stats["Packets"] / total_packets * 100
        stats["Mbit/s"] = (stats["Bytes"] * 8) / (len(packets) * 10**6)
        stats["End Packets"] = stats["Packets"]
        stats["End Bytes"] = stats["Bytes"]
        stats["End Bits/s"] = stats["Mbit/s"]

    return protocol_stats

def save_protocol_stats_to_csv(protocol_stats, output_file):
    df = pd.DataFrame.from_dict(protocol_stats, orient="index")
    df.index.name = "Protocol Path"
    df.reset_index(inplace=True)
    df.to_csv(output_file, index=False)


def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)

    five_tuple_info = []
    packet_lengths = []
    packet_timestamps = []

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = None
            dst_port = None
            protocol = packet[IP].proto

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            five_tuple_info.append((src_ip, src_port, dst_ip, dst_port, protocol))

        packet_length = len(packet)
        packet_lengths.append(packet_length)
        packet_timestamps.append(float(packet.time))

    # 统计数据包长度
    packet_length_stats = {
        "0-49": {"count": 0, "percentage": 0, "max_length": np.nan, "min_length": np.nan},
        "50-109": {"count": 0, "percentage": 0, "max_length": np.nan, "min_length": np.nan},
        "110-319": {"count": 0, "percentage": 0, "max_length": np.nan, "min_length": np.nan},
        "320-639": {"count": 0, "percentage": 0, "max_length": np.nan, "min_length": np.nan},
        "640-1279": {"count": 0, "percentage": 0, "max_length": np.nan, "min_length": np.nan},
        "1280-2559": {"count": 0, "percentage": 0, "max_length": np.nan, "min_length": np.nan},
        "2560-5119": {"count": 0, "percentage": 0, "max_length": np.nan, "min_length": np.nan},
        "5120-inf": {"count": 0, "percentage": 0, "max_length": np.nan, "min_length": np.nan}
    }

    for length in packet_lengths:
        if length >= 0 and length <= 49:
            packet_length_stats["0-49"]["count"] += 1
        elif length >= 50 and length <= 109:
            packet_length_stats["50-109"]["count"] += 1
        elif length >= 110 and length <= 319:
            packet_length_stats["110-319"]["count"] += 1
        elif length >= 320 and length <= 639:
            packet_length_stats["320-639"]["count"] += 1
        elif length >= 640 and length <= 1279:
            packet_length_stats["640-1279"]["count"] += 1
        elif length >= 1280 and length <= 2559:
            packet_length_stats["1280-2559"]["count"] += 1
        elif length >= 2560 and length <= 5119:
            packet_length_stats["2560-5119"]["count"] += 1
        else:
            packet_length_stats["5120-inf"]["count"] += 1

    total_packets = len(packet_lengths)

    for key in packet_length_stats:
        count = packet_length_stats[key]["count"]
        packet_length_stats[key]["percentage"] = (count / total_packets) * 100

    # 计算每个区间的最大长度和最小长度
    for packet in packets:
        length = len(packet)
        if length >= 0 and length <= 49:
            if np.isnan(packet_length_stats["0-49"]["max_length"]) or length > packet_length_stats["0-49"]["max_length"]:
                packet_length_stats["0-49"]["max_length"] = length
            if np.isnan(packet_length_stats["0-49"]["min_length"]) or length < packet_length_stats["0-49"]["min_length"]:
                packet_length_stats["0-49"]["min_length"] = length
        elif length >= 50 and length <= 109:
            if np.isnan(packet_length_stats["50-109"]["max_length"]) or length > packet_length_stats["50-109"]["max_length"]:
                packet_length_stats["50-109"]["max_length"] = length
            if np.isnan(packet_length_stats["50-109"]["min_length"]) or length < packet_length_stats["50-109"]["min_length"]:
                packet_length_stats["50-109"]["min_length"] = length
        elif length >= 110 and length <= 319:
            if np.isnan(packet_length_stats["110-319"]["max_length"]) or length > packet_length_stats["110-319"]["max_length"]:
                packet_length_stats["110-319"]["max_length"] = length
            if np.isnan(packet_length_stats["110-319"]["min_length"]) or length < packet_length_stats["110-319"]["min_length"]:
                packet_length_stats["110-319"]["min_length"] = length
        elif length >= 320 and length <= 639:
            if np.isnan(packet_length_stats["320-639"]["max_length"]) or length > packet_length_stats["320-639"]["max_length"]:
                packet_length_stats["320-639"]["max_length"] = length
            if np.isnan(packet_length_stats["320-639"]["min_length"]) or length < packet_length_stats["320-639"]["min_length"]:
                packet_length_stats["320-639"]["min_length"] = length
        elif length >= 640 and length <= 1279:
            if np.isnan(packet_length_stats["640-1279"]["max_length"]) or length > packet_length_stats["640-1279"]["max_length"]:
                packet_length_stats["640-1279"]["max_length"] = length
            if np.isnan(packet_length_stats["640-1279"]["min_length"]) or length < packet_length_stats["640-1279"]["min_length"]:
                packet_length_stats["640-1279"]["min_length"] = length
        elif length >= 1280 and length <= 2559:
            if np.isnan(packet_length_stats["1280-2559"]["max_length"]) or length > packet_length_stats["1280-2559"]["max_length"]:
                packet_length_stats["1280-2559"]["max_length"] = length
            if np.isnan(packet_length_stats["1280-2559"]["min_length"]) or length < packet_length_stats["1280-2559"]["min_length"]:
                packet_length_stats["1280-2559"]["min_length"] = length
        elif length >= 2560 and length <= 5119:
            if np.isnan(packet_length_stats["2560-5119"]["max_length"]) or length > packet_length_stats["2560-5119"]["max_length"]:
                packet_length_stats["2560-5119"]["max_length"] = length
            if np.isnan(packet_length_stats["2560-5119"]["min_length"]) or length < packet_length_stats["2560-5119"]["min_length"]:
                packet_length_stats["2560-5119"]["min_length"] = length
        else:
            if np.isnan(packet_length_stats["5120-inf"]["max_length"]) or length > packet_length_stats["5120-inf"]["max_length"]:
                packet_length_stats["5120-inf"]["max_length"] = length
            if np.isnan(packet_length_stats["5120-inf"]["min_length"]) or length < packet_length_stats["5120-inf"]["min_length"]:
                packet_length_stats["5120-inf"]["min_length"] = length

    # 统计I/O吞吐量
    throughput = {}
    prev_timestamp = packet_timestamps[0]
    packets_per_sec = 0

    for i in range(1, len(packet_timestamps)):
        curr_timestamp = packet_timestamps[i]
        if curr_timestamp - prev_timestamp >= 1:
            throughput[int(prev_timestamp)] = packets_per_sec
            prev_timestamp = curr_timestamp
            packets_per_sec = 1
        else:
            packets_per_sec += 1

    return five_tuple_info, packet_length_stats, throughput

def save_five_tuple_to_csv(five_tuple_info, csv_file):
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol'])
        writer.writerows(five_tuple_info)

def save_packet_length_to_excel(packet_length_stats, excel_file):
    df = pd.DataFrame.from_dict(packet_length_stats, orient='index')
    df.index.name = 'Length Range'
    df.reset_index(inplace=True)
    df.columns = ['Length Range', 'Count', 'Percentage', 'Max Length', 'Min Length']
    df.to_excel(excel_file, index=False)

def plot_throughput(throughput):
    plt.plot(list(throughput.keys()), list(throughput.values()))
    plt.xlabel('Time (s)')
    plt.ylabel('Packets per Second')
    plt.title('Packets per Second Over Time')
    plt.show()


if __name__ == "__main__":
    pcap_file = "video.pcap"
    output_file = "protocol_stats.csv"
    pcap_file = "video.pcap"
    csv_file = "five_tuple_info.csv"
    excel_file = "packet_length_stats.xlsx"
    protocol_stats = analyze_protocol_hierarchy(pcap_file)
    save_protocol_stats_to_csv(protocol_stats, output_file)
    five_tuple_info, packet_length_stats, throughput = analyze_pcap(pcap_file)
    save_five_tuple_to_csv(five_tuple_info, csv_file)
    save_packet_length_to_excel(packet_length_stats, excel_file)
    plot_throughput(throughput)

