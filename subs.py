import codecs

def decode_eth_header(header_contents: str) -> Optional[dict]:
    """Breaks up string containing ethernet header into the various components
    of the header. This is done with a dictionary, where the key is the
    descriptor and the value is the section of the header that matches.

    Args:
        header_contents (str): String containing header contents

    Returns:
        Optional[dict]: Dictionary containing split headers into sections. This
        may also be a None returned if the header length is found to not
        be sufficient.
    """
    if len(header_contents) >= 28:
        output_dict = {}
        output_dict["full_contents"] = header_contents
        output_dict["src_mac_addr"] = header_contents[0:12]
        output_dict["dest_mac_addr"] = header_contents[12:24]
        output_dict["type"] = header_contents[24:28]
        return output_dict
    else:
        return None

def decode_ip_header(header_contents: str) -> Optional[dict]:
    """ Breaks up a string containing the IP header into the various sections
    using a dictionary. This also decodes certain values (i.e. converts them
    to the character / decimal equivalents appropriately) using a separate
    decoding function.

    Args:
        header_contents (str): String containing header contents

    Returns:
        Optional[dict]: Dictionary containing headers split into sections. If
        the header is invalid, this will be None.
    """
    if len(header_contents) >= 40:
        output_dict = {}
        output_dict["full_contents"] = header_contents
        output_dict["ip_version"] = header_contents[0:1]
        output_dict["ip_header_len"] = header_contents[1:2]
        output_dict["service_type"] = header_contents[2:4]
        output_dict["datagram_len"] = header_contents[4:8]
        output_dict["datagram_len_decoded"] = decode_hex(output_dict[
            "datagram_len"])
        output_dict["time_to_live"] = header_contents[16:18]
        output_dict["time_to_live_decoded"] = decode_hex(output_dict[
            "time_to_live"])
        output_dict["transport_protocol"] = header_contents[18:20]
        output_dict["ip_header_checksum"] = header_contents[20:24]
        output_dict["source_ip_addr"] = header_contents[24:32]
        output_dict["source_ip_addr_decoded"] = decode_ip_address(
                output_dict["source_ip_addr"])
        output_dict["dest_ip_addr"] = header_contents[32:40]
        output_dict["dest_ip_addr_decoded"] = decode_ip_address(
                output_dict["dest_ip_addr"])
        return output_dict
    else:
        return None

def decode_tcp_header(header_contents: str) -> Optional[dict]:
    """Breaks up a string containing the TCP header in various sections using a
    dictionary. Also decodes certain values using a separate decoding function.

    Args:
        header_contents (str): String containing header contents

    Returns:
        Optional[dict]: Dictionary containing header split into sections. If
        header is invalid, this will be a None.
    """
    if len(header_contents) >= 64:
        output_dict = {}
        output_dict["full_contents"] = header_contents
        output_dict["source_port"] = header_contents[0:4]
        output_dict["dest_port"] = header_contents[4:8]
        output_dict["seq_num"] = header_contents[8:16]
        output_dict["seq_num_decoded"] = decode_hex(output_dict[
            "seq_num"])
        output_dict["ack_num"] = header_contents[16:24]
        output_dict["ack_num_decoded"] = decode_hex(output_dict[
            "ack_num"])
        output_dict["tcp_header_len"] = header_contents[24:25]
        output_dict["tcp_header_checksum"] = header_contents[32:36]
        return output_dict
    else:
        return None

def decode_http_data(packet_contents: str) -> Optional[dict]:
    """Creates a dictionary containing the HTTP data and the decoded version.

    Args:
        packet_contents (str): String containing contents of packet

    Returns:
        Optional[dict]: Dictionary containing the data and the decoded form. If
        the length of the data is 0 there is no HTTP data in the packet, so the
        return is None.
    """
    if len(packet_contents) > 0:
        output_dict = {}
        output_dict["full_contents"] = packet_contents
        decoded = codecs.decode(packet_contents.strip(), "hex")
        output_dict["data"] = decoded
        output_dict["data_decoded"] = decode_hex(output_dict[
            "data"], True)
        return output_dict
    else:
        return None

def decode_hex(data: str, text:bool = False) -> Union[int,str]:
    """Function to decode an input hex string into either the integer
    equivalent or the text equivalent depending on the flag passed.

    Args:
        data (str): String of hex data
        text (bool, optional): Flag to denote whether input is text or not.
        Defaults to False.

    Returns:
        Union[int,str]: Return is either the integer equivalent or the string
        containing the text equivalent of the given hex string.
    """
    decoded = None
    if text:
        data = data.hex()
        decoded = codecs.decode(data.strip(), "hex").decode("utf-8")
    else:
        decoded = int(data, 16)
    return decoded

def decode_ip_address(hex_string: str) -> str:
    """Function to decode IP address from hexadecimal representation to the
    human friendly format with periods separating octets e.g. 127.0.0.1

    Args:
        hex_string (str): hexadecimal representation

    Returns:
        str: human friendly octet format of hexadecimal representation
    """
    chunks = [hex_string[i:i+2] for i in range(0,len(hex_string),2)]
    decoded_list = [str(int(i, 16)) for i in chunks]
    decoded_string = ".".join(decoded_list)
    return decoded_string
