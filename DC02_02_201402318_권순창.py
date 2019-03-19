import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print("======ethernet header======")
    print("src_mac_address:", ether_src)
    print("dest_mac_address:", ether_dest)
    print("ip_version", ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr 

def parsing_internet_header(data):
    internet_header = struct.unpack("!1c1c2s2s2s1c1c2s4c4c", data)
    ip_vers = (int(internet_header[0].hex(),16)&240)>>4
    ip_length = (int(internet_header[0].hex(),16))&15
    differ_serv = (int(internet_header[1].hex(),16)&252)>>2
    explicit = int(internet_header[1].hex(),16)&3
    total_leng = int(internet_header[2].hex(),16)
    identifi = int(internet_header[3].hex(),16)
    flags = "0x" +internet_header[4].hex()
    res_bit = ((int(internet_header[4].hex(),16))&32768)>>15
    do_frag = ((int(internet_header[4].hex(),16))&16384)>>14
    mo_frag = ((int(internet_header[4].hex(),16))&8192)>>13
    frag_off = ((int(internet_header[4].hex(),16)))&8191
    timetolive = int(internet_header[5].hex(),16)
    protocol = int(internet_header[6].hex(),16)
    Header = "0x" + (internet_header[7].hex())
    inter_src = convert_internet_address(internet_header[8:12])
    inter_dst = convert_internet_address(internet_header[12:16])
    print("======ip header======")
    print("ip_version:", ip_vers)
    print("ip_length:", ip_length)
    print("differentiated_service_codepoint:", differ_serv)
    print("explicit_congestion_codepoint:",)
    print("total_length:", total_leng)
    print("identification:", identifi)
    print("flags:", flags)
    print(">>>reserved bit:", res_bit)
    print(">>>not_fragments:", do_frag)
    print(">>>fragments:", mo_frag)
    print(">>>fragments_offset:", frag_off)
    print("Time to live:", timetolive)
    print("protocol:", protocol)
    print("header checksum:", Header)
    print("source_ip_address:", inter_src)
    print("dest_ip_address:", inter_dst)
    

def convert_internet_address(data):
    internet_addr = list()
    for i in data:
        internet_addr.append(str(int(i.hex(),16)))
    internet_addr = ".".join(internet_addr) 
    return internet_addr

def parsing_tcp_header(data):
    tcp_header = struct.unpack("!2s2s4s4s2s2s2s2s", data)
    tcp_srcport = int(tcp_header[0].hex(),16)
    tcp_dstport = int(tcp_header[1].hex(),16)
    tcp_seq = int(tcp_header[2].hex(),16)
    tcp_ack = int(tcp_header[3].hex(),16)
    tcp_headleng = int(tcp_header[4].hex()[0],16)
    tcp_flags = int(tcp_header[4].hex()[1:4],16)
    flags_binary = bin(int(tcp_header[4].hex(),16))[1:18]
    tcp_res = int(flags_binary[4:6],2)
    tcp_non = int(flags_binary[7],2)
    tcp_cwr = int(flags_binary[8],2)
    tcp_ecr = int(flags_binary[9],2)
    tcp_urg = int(flags_binary[10],2)
    tcp_ack = int(flags_binary[11],2)
    tcp_pus = int(flags_binary[12],2)
    tcp_rst = int(flags_binary[13],2)
    tcp_syn = int(flags_binary[14],2)
    tcp_fin = int(flags_binary[15],2)
    sizevl = int (tcp_header[5].hex(),16)
    tcp_checksum = int(tcp_header[6].hex(),16)
    urgpointer = int(tcp_header[7].hex(),16)
    print("======TCP header======")
    print("src_port:", tcp_srcport)
    print("dec_port:", tcp_dstport)
    print("seq_num:", tcp_seq)
    print("ack_num:", tcp_ack)
    print("header:", tcp_srcport)
    print("flags:", tcp_dstport)
    print(">>>reserved:", tcp_res)
    print(">>>nonce:", tcp_non)
    print(">>>cwr:", tcp_cwr)
    print(">>>ecr:", tcp_ecr)
    print(">>>urgent:", tcp_urg)
    print(">>>ack:", tcp_ack)
    print(">>>push:", tcp_pus)
    print(">>>reset:", tcp_rst)
    print(">>>syn:", tcp_syn)
    print(">>>fin:", tcp_fin)
    print("window_size_value:", sizevl)
    print("checksum:", tcp_checksum)
    print("urgent_pointer:", urgpointer)

def parsing_udp_header(data):
    udp_header = struct.unpack("!2s2s2s2s", data)
    udp_srcport = int(udp_header[0].hex(),16)
    udp_dstport = int(udp_header[1].hex(),16)
    udp_leng = int(udp_header[2].hex(),16)
    udp_hdck = int(udp_header[3].hex(),16)
    print("======udp header======")
    print("src_port:", udp_srcport)
    print("dec_port:", udp_dstport)
    print("leng:", udp_leng)
    print("header checksum:", udp_hdck)

recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))

while True:
    print("<<<<<<Packet Capture Start>>>>>>")
    data = recv_socket.recvfrom(20000)
    parsing_ethernet_header(data[0][0:14])
    parsing_internet_header(data[0][14:34])
    check = data[0][23]
    if check == 6:
        parsing_tcp_header(data[0][34:54])
    elif check == 17:
        parsing_udp_header(data[0][34:42])
