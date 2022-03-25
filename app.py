# ============== ALL IMPORTS ==================================================
from flask import (Flask, render_template, redirect, url_for, session, request
        )
import subprocess as sc
import time
import subs

# ============== FLASK INITIALISATION =========================================

app = Flask(__name__)
with open('secret_key.txt', 'r') as f:
    app.secret_key = f.readline().strip()

# ============== FLASK ROUTES =================================================

@app.route("/")
def landing_page() -> None:
    return render_template("landing_page.html")

@app.route("/request", methods = ["POST","GET"])
def first_page():
    current_time = str(time.time_ns())
    client_ip = request.remote_addr
    # Use subprocess library to call the sniffer script
    output_from_sniffer_call = sc.Popen(["sudo", "./run-sniffer.sh", "-f",
        current_time, "-ip", client_ip], stdout = sc.PIPE,
        stderr = sc.PIPE)
    session["time_value"] = current_time
    session["client_ip"] = client_ip
    time.sleep(0.25)
    return render_template("request.html")

@app.route('/loading')
def load_data() -> None:
    return render_template("loading.html")

@app.route("/a-level")
def a_level() -> None:
    file_to_find = session.get("time_value", None) + ".txt"
    with open("output_files/"+file_to_find, "r") as f:
        contents = f.read().splitlines()

    # Go through contents of file and decode each relevant header
    eth_headers = list()
    ip_headers = list()
    tcp_headers = list()
    http_data = list()
    for i in range (0, len(contents), 4):
        eth_headers.append(subs.decode_eth_header(contents[i]))
        ip_headers.append(subs.decode_ip_header(contents[i+1]))
        tcp_headers.append(subs.decode_tcp_header(contents[i+2]))
        http_data.append(subs.decode_http_data(contents[i+3]))

    client_ip = session["client_ip"]
    # Pass the various headers and packet data to the template
    return render_template("a-level.html", eth = eth_headers, ip = ip_headers,
            tcp = tcp_headers, http = http_data, client_ip = client_ip)
