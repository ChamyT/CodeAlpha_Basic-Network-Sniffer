import socket
import struct

def unpack_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))

def unpack_ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = unpack_ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}')

        if eth_proto == 8:  # IPv4
            ttl, proto, src_ip, target_ip, data = unpack_ipv4_packet(data)
            print('IPv4 Packet:')
            print(f'Source IP: {src_ip}, Target IP: {target_ip}, TTL: {ttl}, Protocol: {proto}')

if __name__ == "__main__":
    main()
