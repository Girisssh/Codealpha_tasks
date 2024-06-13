import socket
import struct
import textwrap

def main():
    try:
        # Create a raw socket to capture all network traffic
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except (PermissionError, socket.error) as e:
        print(f"Error: {e}")
        return

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f"\t- Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")

        if eth_proto == 8:  # IPv4
            ipv4_info = ipv4_packet(data)
            if ipv4_info:
                version, header_length, ttl, proto, src, target, data = ipv4_info
                print(f"\t- IPv4 Packet:")
                print(f"\t\t- Version: {version}, Header Length: {header_length}, TTL: {ttl}")
                print(f"\t\t- Protocol: {proto}, Source: {src}, Target: {target}")

                if proto == 1:  # ICMP
                    icmp_info = icmp_packet(data)
                    if icmp_info:
                        icmp_type, code, checksum, data = icmp_info
                        print(f"\t- ICMP Packet:")
                        print(f"\t\t- Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
                        print(f"\t\t- Data:")
                        print(format_multi_line("\t\t\t", data))

                elif proto == 6:  # TCP
                    tcp_info = tcp_segment(data)
                    if tcp_info:
                        src_port, dest_port, sequence, acknowledgement, flags, data = tcp_info
                        print(f"\t- TCP Segment:")
                        print(f"\t\t- Source Port: {src_port}, Destination Port: {dest_port}")
                        print(f"\t\t- Sequence: {sequence}, Acknowledgement: {acknowledgement}")
                        print(f"\t\t- Flags: {flags}")
                        print(f"\t\t- Data:")
                        print(format_multi_line("\t\t\t", data))

                elif proto == 17:  # UDP
                    udp_info = udp_segment(data)
                    if udp_info:
                        src_port, dest_port, length, data = udp_info
                        print(f"\t- UDP Segment:")
                        print(f"\t\t- Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}")
                        print(f"\t\t- Data:")
                        print(format_multi_line("\t\t\t", data))
            else:
                print(f"\t- Error: Invalid IPv4 packet")
        else:
            print(f"\t- Data:")
            print(format_multi_line("\t", data))


def ethernet_frame(data):
    """Unpack Ethernet frame."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    """Return properly formatted MAC address (i.e AA:BB:CC:DD:EE:FF)."""
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    """Unpack IPv4 packet."""
    if len(data) < 20:
        return None
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    if len(data) < header_length:
        return None
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    """Return properly formatted IPv4 address (i.e 192.168.1.1)."""
    return '.'.join(map(str, addr))

def icmp_packet(data):
    """Unpack ICMP packet."""
    if len(data) < 4:
        return None
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    """Unpack TCP segment."""
    if len(data) < 20:
        return None
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    if len(data) < offset:
        return None
    flags = {
        'URG': (offset_reserved_flags & 32) >> 5,
        'ACK': (offset_reserved_flags & 16) >> 4,
        'PSH': (offset_reserved_flags & 8) >> 3,
        'RST': (offset_reserved_flags & 4) >> 2,
        'SYN': (offset_reserved_flags & 2) >> 1,
        'FIN': offset_reserved_flags & 1
    }
    return src_port, dest_port, sequence, acknowledgement, flags, data[offset:]

def udp_segment(data):
    """Unpack UDP segment."""
    if len(data) < 8:
        return None
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=80):
    """Format multi-line data."""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == '__main__':
    main()