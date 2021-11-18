import socket
import struct
import textwrap

def main():
    tab_1="\t"
    tab_2="\t\t"
    tab_3="\t\t\t"
    tab_4="\t\t\t\t"
    conn=socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(3))


    while True:

        raw_data, addr=conn.recvfrom(66536)
        print("addr: ", addr)
        dest_mac, src_mac, eth_proto, data = frame(raw_data)
        print("\nEthernet Frame: ")
        print(tab_1 + "Destination: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))

        if eth_proto==8:
            (version, header_length, ttl, proto, src_ip, dest_ip, data)=ipv4_packet(data)
            print(tab_1 + "IPv4 Packet: ")
            print(tab_2 + "version: {}, Header Length: {}, ttl: {}".format(version, header_length, ttl))
            print(tab_2 + "proto: {}, Source IP: {}, Destintion IP: {}".format(proto, src_ip, dest_ip))

            #Icmp
            if(proto==1):
                icmp_type, code, checksum, data=icmp_packet(data)
                print(tab_1 + "ICMP Packet: ")
                print(tab_2 + "Type: {}, Code:{}, CheckSum: {}, ".format(icmp_type, code, checksum))
                print(tab_2+ "DATA: ")
                print(format_multiline(tab_3, data))
            #tcp
            elif(proto==6):
                (src_port, dest_port, sequence, acknowledgement, offset, flag_urg, flag_ack, flag_fin, flag_psh, flag_rst, flag_syn, data)=tcp_packet(data)
                print(tab_1 + " TCP Packet: ")
                print(tab_2 + "Source Port: {}, Destination Port: {}".format(src_port, dest_port))
                print(tab_2 + "Sequence: {}, Acknowledgment: {}".format(sequence, acknowledgement))
                print(tab_2 + "Flags: ")
                print(tab_3 + "Urg: {}, ACK:{}, PSH:{}, RST:{}, SYN:{}, FIN:{}".format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(tab_2+ "DATA: ")
                print(format_multiline(tab_3, data))

            #udp
            elif(proto==17):
                src_port, dest_port, length, data=udp(data)
                print(tab_1 + "UDP Segment: ")
                print(tab_2 + "Source Port: {}, Destination Port: {}, Length: {}".format(src_port, dest_port, length))
            #other print data
            else:
                print(tab_1+"Data: ")
                print(format_multiline(tab_2, data))





def frame(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    #htons sets in network order
    return (get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[14:])

def get_mac(bytes_addr):
    #{02x} converts to hex
    bytes_str=map('{:02x}'.format, bytes_addr)
    #example FF:FF:FF:FF:FF:FF
    mac_addr=":".join(bytes_str).upper()
    return mac_addr
def get_IP(addr):
    # print("unformatted address: ", addr)
    return '.'.join(map(str,addr))

def ipv4_packet(data):
    version_header_length=data[0]
    version=version_header_length>>4
    header_length=(version_header_length & 15)*4
    #B option is unsigned char 1 byte long
    #x is a pad character for first part of ip_packet and header checksum
    #4s is 32 bits long
    ttl, proto, src, target=struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_length, ttl, proto, get_IP(src), get_IP(target), data[header_length:]

def icmp_packet(data):
    icmp_type, code, checksum=struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_packet(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags=struct.unpack("! H H L L H", data[:14])
    offset=(offset_reserved_flags>>12)*4
    flag_urg=(offset_reserved_flags & 32)>>5
    flag_ack=(offset_reserved_flags & 16)>>5
    flag_psh=(offset_reserved_flags & 8)>>5
    flag_rst=(offset_reserved_flags & 4)>>5
    flag_syn=(offset_reserved_flags & 2)>>5
    flag_fin=(offset_reserved_flags & 1)>>5
    return src_port, dest_port, sequence, acknowledgement, offset, flag_urg, flag_ack, flag_fin, flag_psh, flag_rst, flag_syn, data[offset:]

def udp(data):
    src_port, dest_port, size=struct.unpack("! H H 2x H", data[:8])
    return(src_port, dest_port, size, data[8:])
#found online
def format_multiline(prefix, string, size=80):
    size-=len(prefix)
    if isinstance(string, bytes):
        string="".join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size-=1
    return "\n".join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == "__main__":
    main()



