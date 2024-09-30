import scapy.all as scapy

# Function to write packet data to a file
def save_packet(packet):
    with open("captured_packets.txt", "a") as f:
        f.write(str(packet) + "\n")

# Callback function for packet processing
def packet_callback(packet):
    print(packet.summary())  # Print to console
    save_packet(packet)       # Save to file

# Start sniffing
scapy.sniff(prn=packet_callback, count=10)  # Adjust count as needed

