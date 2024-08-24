from scapy.all import sniff,IP,TCP,UDP,Raw

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        if proto == 6:
            protocol = "TCP"

        elif proto == 17:
            protocol = "UDP"

        else:
            protocol ="Other"

        payload = ""
        if Raw in packet:
            payload = packet[Raw].load.decode(errors='ignore')


            print(f"Source IP: {ip_src}")
            print(f"Destination IP: {ip_dst}")
            print(f"Protocol: {protocol}")
            print(f"Payload: {payload[:100]}") # show only the first 100 characters of payload
            print("-" * 50)


def main():
    print("String packet capture.Press CTRL+C to stop.")
    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("Packet capture stopped.")

if __name__ == "__main__":
    main()