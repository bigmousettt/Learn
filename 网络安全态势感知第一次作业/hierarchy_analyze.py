from scapy.all import *
import pandas as pd

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

if __name__ == "__main__":
    pcap_file = "video.pcap"
    output_file = "protocol_stats.csv"

    protocol_stats = analyze_protocol_hierarchy(pcap_file)
    save_protocol_stats_to_csv(protocol_stats, output_file)


# # 示例用法
# pcap_file = "video.pcap"
# csv_file = "protocol_hierarchy_stats.csv"
# protocol_stats = analyze_protocol_hierarchy(pcap_file)
# save_protocol_hierarchy_to_csv(protocol_stats, csv_file)
