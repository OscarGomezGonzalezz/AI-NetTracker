from scapy.all import sniff
import pandas as pd
from collections import defaultdict
import time

# Estructuras para estadísticas
traffic_stats = defaultdict(lambda: {"packet_count": 0, "byte_count": 0, "packet_lengths": [], "ports": set()})

# Lista para guardar características procesadas
processed_data = []

def packet_callback(packet):
    if packet.haslayer('IP'):
        # Información básica del paquete
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        src_port = packet.sport if hasattr(packet, 'sport') else None
        dst_port = packet.dport if hasattr(packet, 'dport') else None
        protocol = packet.proto
        length = len(packet)
        timestamp = time.time()

        # Statistics for trainging the AI model
        traffic_stats[src_ip]["packet_count"] += 1
        traffic_stats[src_ip]["byte_count"] += length
        traffic_stats[src_ip]["packet_lengths"].append(length)
        if src_port:
            traffic_stats[src_ip]["ports"].add(src_port)
        if dst_port:
            traffic_stats[dst_ip]["ports"].add(dst_port)

        # Calcular estadísticas avanzadas
        src_stats = traffic_stats[src_ip]
        dst_stats = traffic_stats[dst_ip]

        features = {
            "Timestamp": timestamp,
            "Src IP": src_ip,
            "Dst IP": dst_ip,
            "Src Port": src_port,
            "Dst Port": dst_port,
            "Protocol": protocol,
            "Length": length,
            "Src Packet Count": src_stats["packet_count"],
            "Dst Packet Count": dst_stats["packet_count"],
            "Src Byte Count": src_stats["byte_count"],
            "Dst Byte Count": dst_stats["byte_count"],
            "Src Port Count": len(src_stats["ports"]),
            "Dst Port Count": len(dst_stats["ports"]),
            "Src Length StdDev": (pd.Series(src_stats["packet_lengths"]).std() if len(src_stats["packet_lengths"]) > 1 else 0),
            "Dst Length StdDev": (pd.Series(dst_stats["packet_lengths"]).std() if len(dst_stats["packet_lengths"]) > 1 else 0),
        }

        processed_data.append(features)

        # Guardar los datos cada 100 paquetes
        if len(processed_data) % 100 == 0:
            df = pd.DataFrame(processed_data)
            df.to_csv("data/network_traffic.csv", index=False)
            print("Saved 100 packets to CSV")

# Capturar paquetes
sniff(prn=packet_callback, store=0, iface="en0", count=1000)
