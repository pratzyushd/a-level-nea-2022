def decode_eth_header(header_contents):
    if len(header_contents) == 28:
        output_dict = {}
        output_dict["src_mac_addr"] = header_contents[0:12]
        output_dict["dest_mac_addr"] = header_contents[12:24]
        output_dict["type"] = header_contents[24:28]
        return output_dict
    else:
        return None

def decode_ip_header(header_contents):
    if len(header_contents) == 40:
        output_dict = {}
        output_dict["ip_version"] = header_contents[0:1]
        output_dict["ip_header_len"] = header_contents[1:2]
        output_dict["service_type"] = header_contents[2:4]
        output_dict["datagram_len"] = header_contents[4:8]
        output_dict["time_to_live"] = header_contents[16:18]
        output_dict["transport_protocol"] = header_contents[18:20]
        output_dict["ip_header_checksum"] = header_contents[20:24]
        output_dict["source_ip_addr"] = header_contents[24:32]
        output_dict["dest_ip_addr"] = header_contents[32:40]
        return output_dict
    else:
        return None

def decode_tcp_header(header_contents):
    if len(header_contents) == 36:
        output_dict = {}
        output_dict["source_port"] = header_contents[0:4]
        output_dict["dest_port"] = header_contents[4:8]
        output_dict["seq_num"] = header_contents[8:16]
        output_dict["ack_num"] = header_contents[16:24]
        output_dict["tcp_header_len"] = header_contents[24:25]
        output_dict["tcp_header_checksum"] = header_contents[32:36]
        return output_dict
    else:
        return None

def decode_packet_data(packet_contents):
    if len(packet_contents) > 0:
        output_dict = {}
        # TODO: write the actual decoding algorithm here
        output_dict["data"] = packet_contents
        return output_dict
    else:
        return None

