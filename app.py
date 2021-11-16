from flask import Flask, render_template, redirect, url_for, session
import subprocess as sc
import time
import subs

# ============== FLASK ROUTES ===============================

app = Flask(__name__)
with open('secret_key.txt', 'r') as f:
    app.secret_key = f.readline().strip()

@app.route("/")
def introduce():
    return redirect(url_for("first_page"))

@app.route("/hello")
def first_page():
    return render_template("hello.html")

@app.route('/loading')
def call_sniffer():
    current_time = str(time.time_ns())
    # Use subprocess library to call the sniffer script
    output_from_sniffer_call = sc.Popen(["sudo", "./run-sniffer.sh", "-f",
                                         current_time],
                                    stdout = sc.PIPE, stderr = sc.PIPE)
    session["time_value"] = current_time
    return render_template("loading.html")

@app.route("/a-level")
def a_level():
    file_to_find = session.get("time_value", None) + ".txt"
    with open("output_files/"+file_to_find, "r") as f:
        contents = f.readlines()
        # TODO: Filter by IP address here
        #for i in range(0, (len(contents)-1)/4):
            #ip_addr = contents[i*4 + 1][24:32]
    
    # Raw headers and data
    eth_header = contents[0]
    ip_header = contents[1]
    tcp_header = contents[2]
    packet_data = contents[3]

    # Processed data
    # TODO: create function that does all of the below and constructs a dictionary
    # with the values / names of the sections as the key
    # Source IP address
    hex_src_ip = ip_header[24:32]
    conv_src_ip = [int(hex_src_ip[i:i+2],16) for i in range(0, len(hex_src_ip), 2)]
    conv_src_ip_str = ".".join(map(str, conv_src_ip))

    # Destination IP address
    hex_dest_ip = ip_header[32:40]
    conv_dest_ip = [int(hex_dest_ip[i:i+2],16) for i in range(0, len(hex_dest_ip), 2)]
    conv_dest_ip_str = ".".join(map(str, conv_dest_ip))

    # Source TCP port
    hex_src_port = tcp_header[0:4]
    conv_src_port = [int(hex_src_port[i:i+2],16) for i in range(0, len(hex_src_port), 2)]
    conv_src_port_str = ".".join(map(str, conv_src_port))
    
    # Destination TCP port
    hex_dest_port = tcp_header[4:8]
    conv_dest_port = [int(hex_dest_port[i:i+2],16) for i in range(0, len(hex_src_port), 2)]
    conv_dest_port_str = ".".join(map(str, conv_dest_port))


    #packet_decoded = packet_data.decode("utf-8")
    # Pass the various headers and packet data to the template
    return render_template("a-level.html", eth=eth_header, ip=ip_header,
                            tcp=tcp_header, data=packet_data, hex_src_ip = hex_src_ip,
                            conv_src_ip = conv_src_ip_str, hex_dest_ip = hex_dest_ip,
                            conv_dest_ip = conv_dest_ip_str, hex_src_port = hex_src_port,
                            conv_src_port = conv_src_port_str, hex_dest_port = hex_dest_port,
                            conv_dest_port = conv_dest_port_str)

