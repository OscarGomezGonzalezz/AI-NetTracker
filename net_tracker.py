from scapy.all import sniff
import pandas as pd
import time

# Esta lista contendrá los paquetes procesados
packet_data = []

def packet_callback(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        src_port = packet.sport if hasattr(packet, 'sport') else None
        dst_port = packet.dport if hasattr(packet, 'dport') else None
        protocol = packet.proto
        length = len(packet)
        timestamp = time.time()

        # Guardamos los datos de los paquetes en una lista
        packet_data.append([timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length])

        # Almacenar los datos en un archivo CSV para su procesamiento posterior
        if len(packet_data) % 100 == 0:  # Guardar cada 100 paquetes
            df = pd.DataFrame(packet_data, columns=["Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Length"])
            df.to_csv("network_traffic.csv", index=False)

# Captura el tráfico de red
sniff(prn=packet_callback, store=0, iface="en0", count=0)
