import socket 
import struct
from termios import TAB1 
import textwrap

from h11 import Data

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def main ():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while  True:   
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'. format(dest_mac, src_mac, eth_proto))
        
        # 8 for IPv4
        if eth_proto == 8:
            (version, header_lenght, ttl, proto, src, target, data) = ipv4_packets(data)
            print(TAB_1 + 'IPv4 Packets: ')
            print(TAB_2 + 'Version: {}, Header Lenght: {}, TTL: {}'. format(version, header_lenght, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'. format(proto, src, target))

            # ICMP
            if proto == 1: 
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet: ')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'. format(icmp_type, code, checksum))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))
            
            # TCP
            elif proto == 6:
                (scr_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin) =tcp_segment(data)
                print(TAB_1 + 'TCP Packet: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'. format(scr_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'. format(sequence, acknowledgement))
                print(TAB_2 + 'Flag: ')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'. format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))
                
            # UDP
            elif proto == 17:
                scr_port, dest_port, lenght, data = udp_packet(data)
                print(TAB_1 + 'UDP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Lenght: {}'. format(scr_port, dest_port, lenght))
            
            # Other
            else:
                print (TAB_1 + 'Data: ')
                print (format_multi_line(DATA_TAB_2,data))
        
        else:
            print ('Data: ')
            print (format_multi_line(DATA_TAB_1,data))
                


# Unpack ethernet frame 
def ethernet_frame(data):
    dest_mac , src_mac , proto = struct.unpack('! 6s 6s H', data [:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formatted MAC address (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper() 

# Unpack IPv4 packets
def ipv4_packets(data):
    version_header_lenght = data[0]
    version = version_header_lenght >> 4
    header_lenght = (version_header_lenght & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version, header_lenght, ttl, proto, ipv4(src), ipv4(target), data[header_lenght:]

# Return properly formatter IPv4 address
def ipv4 (addr):
    return '.'.join(map(str, addr))

# Unpack ICMP packet
def icmp_packet(data):
    icmp_type, code , checksum  = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP packet
def tcp_segment(data):
    (scr_port, dest_port, sequence, acknowledgement, offset_reserved_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 16) >> 4
    flag_psh = (offset_reserved_flag & 8) >> 3
    flag_rst = (offset_reserved_flag & 4) >> 2
    flag_syn = (offset_reserved_flag & 2) >> 1
    flag_fin = offset_reserved_flag & 1
    return scr_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpack TCP packet
def udp_packet(data):
    scr_port, dest_port, size  = struct.unpack('! H H 2x H', data[:8])
    return scr_port, dest_port, size,  data[8:]

# Format multi-line data
def format_multi_line(prefix, string, size=80):
    size-=len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size-=1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])





main()