# ============== ALL IMPORTS ==================================================
from flask import Flask, render_template, redirect, url_for, session
import subprocess as sc
import time
import subs

# ============== FLASK INITIALISATION =========================================

app = Flask(__name__)
with open('secret_key.txt', 'r') as f:
    app.secret_key = f.readline().strip()

# ============== FLASK ROUTES =================================================

@app.route("/")
def landing_page():
    return render_template("landing_page.html") 

@app.route("/request", methods = ["POST","GET"])
def first_page():
    current_time = str(time.time_ns())
    # Use subprocess library to call the sniffer script
    output_from_sniffer_call = sc.Popen(["sudo", "./run-sniffer.sh", "-f",
                                         current_time],
                                    stdout = sc.PIPE, stderr = sc.PIPE)
    session["time_value"] = current_time
    time.sleep(0.25)
    return render_template("request.html")

@app.route('/loading')
def load_data():
    return render_template("loading.html")

@app.route("/a-level")
def a_level():
    file_to_find = session.get("time_value", None) + ".txt"
    with open("output_files/"+file_to_find, "r") as f:
        contents = f.readlines()
    
    eth_header = list()
    ip_header = list()
    tcp_header = list()
    packet_data = list()
    # Go through contents of file and decode each relevant header
    for i in range (0, len(contents), 4):
        eth_header = subs.decode_eth_header(contents[i])
        ip_header = subs.decode_ip_header(contents[i+1])
        tcp_header = subs.decode_tcp_header(contents[i+2])
        packet_data = subs.decode_packet_data(contents[i+3])

    # Pass the various headers and packet data to the template
    return render_template("a-level.html", eth = eth_header, ip = ip_header,
            tcp = tcp_header, data = packet_data)
