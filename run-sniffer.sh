#!/usr/bin/python3
import socket
import os
import argparse as ap

# Class definitions
class Header():
    def __init__(self, content):
       self._content = content.hex()

    def get_content(self):
        return self._content


class EthHeader(Header):
    def __init__(self, content):
        super(EthHeader, self).__init__(content)
        self._content = self._content[0:28]
        self.__source_mac_addr = self._content[0:12]
        self.__dest_mac_addr = self._content[12:24]
        self.__type = self._content[24:28]

    def get_source_mac_addr(self):
        return self.__source_mac_addr

    def get_dest_mac_addr(self):
        return self.__dest_mac_addr

    def get_type(self):
        return self.__type


class IPHeader(Header):
    def __init__(self, content):
        super().__init__(content)
        self._content = self._content[28:68]
        self.__ip_version = self._content[0:1]
        self.__ip_header_len = self._content[1:2]
        self.__service_type = self._content[2:4]
        self.__datagram_len = self._content[4:8]
        self.__time_to_live = self._content[16:18]
        self.__transport_protocol = self._content[18:20]
        self.__ip_header_checksum = self._content[20:24]
        self.__source_ip_addr = self._content[24:32]
        self.__dest_ip_addr = self._content[32:40]

    def get_ip_version(self):
        return self.__ip_version

    def get_ip_header_len(self):
        return self.__ip_header_len

    def get_service_type(self):
        return self.__service_type

    def get_datagram_len(self):
        return self.__datagram_len

    def get_time_to_live(self):
        return self.__time_to_live

    def get_transport_protocol(self):
        return self.__transport_protocol

    def get_ip_header_checksum(self):
        return self.__ip_header_checksum

    def get_source_ip_addr(self):
        return self.__source_ip_addr

    def get_dest_ip_addr(self):
        return self.__dest_ip_addr


class TCPHeader(Header):
    def __init__(self, content):
        super().__init__(content)
        self._content = self._content[68:132]
        self.__source_port = self._content[0:4]
        self.__dest_port = self._content[4:8]
        self.__seq_num = self._content[8:16]
        self.__ack_num = self._content[16:24]
        self.__tcp_header_len = self._content[24:25]
        self.__tcp_header_checksum = self._content[32:36]

    def get_source_port(self):
        return self.__source_port

    def get_dest_port(self):
        return self.__dest_port

    def get_seq_num(self):
        return self.__seq_num

    def get_ack_num(self):
        return self.__ack_num

    def get_tcp_header_len(self):
        return self.__tcp_header_len

    def get_tcp_header_checksum(self):
        return self.__tcp_header_checksum

class Data(Header):
    def __init__(self, content):
        super().__init__(content)
        self._content = self._content[132:]


# Main sniffer program
#sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.ntohs(0x0003))
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
#sock = socket.socket(socket.AF_INET, socket.SOCK_RAW)

# Take in IP address to filter for
# TODO: This needs to be changed to receive the actual IP address from the command line
ip_to_filter = "127.0.0.1"
ip_split = ip_to_filter.split(".")
# Using the .format function, convert the IP address into the hex equivalent
hex_ip_to_filter = "{:02X}{:02X}{:02X}{:02X}".format(*map(int, ip_split))

# Create lists to store the header objects
eth_header_list = list()
ip_header_list = list()
tcp_header_list = list()
data_list = list()

# Create file name based on time passed in from script call
parser = ap.ArgumentParser()
parser.add_argument("-f", "--file-name", type=str, help="File name for output")
args = parser.parse_args()
file_name = args.file_name+".txt"
print(file_name)

# Receiving data from raw socket
# TODO: change the value from just collecting 5 packets to an appropriate
# number
# Could use the IPHeader class and the get_source_ip method to stop after one
# packet from appropriate source is collected
for i in range(5):
    packet = sock.recvfrom(65536)[0]
    eth_header_list.append(EthHeader(packet))
    ip_header_list.append(IPHeader(packet))
    tcp_header_list.append(TCPHeader(packet))
    data_list.append(Data(packet))

# Writing to output file
with open(r"output_files/"+file_name, "w") as f:
    num_to_write = len(eth_header_list)
    for i in range(0, num_to_write):
        #if ip_header_list[i].get_source_ip_addr() == hex_ip_to_filter:
            # Currently just writing entire headers into file
            # This can be changed down the line to be section by section / with
            # labels etc
        f.write(eth_header_list[i].get_content() + os.linesep)
        f.write(ip_header_list[i].get_content() + os.linesep)
        f.write(tcp_header_list[i].get_content() + os.linesep)
        f.write(data_list[i].get_content() + os.linesep)

print("Completed")
