#!/usr/bin/python3
import socket
import argparse as ap
import binascii

# =============== SUBROUTINES TO SPLIT HEADERS ================================

def split_eth_header(contents: str) -> str:
    """Take the full string containing the packet contents and split off the
    ethernet header from it.

    Args:
        contents (str): string containing the full contents of the packet

    Returns:
        str: string of only the ethernet header
    """
    return contents[0:28]

def split_ip_header(contents: str) -> str:
    """Take the full string containing the packet contents and split off the
    IP header from it.

    Args:
        contents (str): string containing the full contents of the packet

    Returns:
        str: string of only the IP header
    """
    return contents[28:68]

def split_tcp_header(contents: str) -> str:
    """Take full string containing packet contents and split off the TCP header
    from it. This function also takes into account SYN packets, which have a
    longer header than other packets, and so adjust the output accordingly.

    Args:
        contents (str): string containing the full contents of the packet

    Returns:
        str: string of only the TCP header
    """
    # If the header is a 40 byte header (i.e. SYN packet), account for this and
    # don't put the additional data as the HTTP data
    if contents[92] == "a":
        return contents[68:148]
    else:
        return contents[68:132]

def split_http_data(contents: str) -> str:
    """Take full string containing packet contents and split of the HTTP
    request data from it. This function, as with the TCP header one, takes into
    account the increased length of SYN packets.

    Args:
        contents (str): string containing full contents of the packet

    Returns:
        str: string of only the HTTP data
    """
    # As above, if TCP header is 40 bytes (i.e. SYN) there is no HTTP data
    if contents[92] == "a":
        return ""
    else:
        return contents[132:]

# ================ PARSING ARGS FROM TERMINAL =================================

# Identify file name based on time passed in through the terminal
parser = ap.ArgumentParser()
parser.add_argument("-f", "--file-name", type=str, help="File name for output")
parser.add_argument("-a", "--address", type=str, help="IPv4 address to "
        "filter for when running sniffer")
args = parser.parse_args()
file_name = args.file_name+".txt"

# Generate hex equivalent of IP address to filter for
raw_ip = args.address
# Uses split function to split IP address into octets. Then use the map
# function and f strings to convert it into the 8 digit hex equivalent address
hex_ip_to_filter = ''.join(f"{i:02x}" for i in map(int,raw_ip.split(".")))


# =================== MAIN SNIFFER PROGRAM ====================================

# Create socket
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

# Create lists to store the header strings
eth_header_list = []
ip_header_list = []
tcp_header_list = []
data_list = []

# Receiving data from raw socket
# This continues sniffing until the whole transaction is completed. This is
# detected by the TCP flags, specifically the SYN and FIN flags for the start
# and end of the transaction.
# Also filters out anything that isn't going to / coming from the correct IP
# address.
transaction_sniffing_complete = False
capturing_enabled = False
tcp_flag_list = []
while not transaction_sniffing_complete:
    raw = sock.recvfrom(65536)[0]
    # Makes use of the binascii lib to turn the bytes object into a parsable
    # hex string, and do regular string handling
    packet = binascii.hexlify(raw).decode()
    # Only allow packets where the given IP address is either the source or the
    # destination
    if hex_ip_to_filter == packet[52:60] or hex_ip_to_filter == packet[60:68]:
        # If the TCP flag indicates a SYN, start capturing packets (transaction
        # has begun)
        if packet[94:96] == "02":
            capturing_enabled = True
        # Ensure packets are only added when capturing is enabled
        if capturing_enabled:
            eth_header_list.append(split_eth_header(packet))
            ip_header_list.append(split_ip_header(packet))
            tcp_header_list.append(split_tcp_header(packet))
            data_list.append(split_http_data(packet))
            # Store list of flags to detect when final flags are received
            tcp_flag_list.append(packet[94:96])
    # If have reached the FIN, FIN-ACK, ACK flags (represented by 11, 11, 10)
    # then transaction is complete, and sniffing can halt
    if tcp_flag_list[-3:] == ["11","11","10"]:
        transaction_sniffing_complete = True


# Writing to output file
with open(r"output_files/"+file_name, "w") as f:
    num_to_write = len(eth_header_list)
    # Entire header written to file, as processing is done by the subroutines
    # in subs.py file
    for i in range(0, num_to_write):
        print(eth_header_list[i], file=f)
        print(ip_header_list[i], file=f)
        print(tcp_header_list[i], file=f)
        print(data_list[i], file=f)
