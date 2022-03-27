# ============== ALL IMPORTS ==================================================
from flask import (Flask, render_template, redirect, url_for, session, request
        )
import subprocess as sc
import time
import subs
import rsa

# ============== FLASK INITIALISATION =========================================

app = Flask(__name__)
# Get the secret key from a text file that is present. Secret keys are used for
# encrypting the session.
with open('secret_key.txt', 'r') as f:
    app.secret_key = f.readline().strip()

# ============== FLASK ROUTES =================================================

# Route for the landing page i.e. the first page you see when you land on the
# website.
@app.route("/")
def landing_page() -> None:
    return render_template("landing_page.html")

# The page that makes the request i.e. starts the sniffer
@app.route("/request", methods = ["POST","GET"])
def first_page() -> None:
    current_time = str(time.time_ns())
    client_ip = request.remote_addr
    # Use subprocess library to call the sniffer script
    output_from_sniffer_call = sc.Popen(["sudo", "./run-sniffer.sh", "-f",
        current_time, "-a", client_ip], stdout = sc.PIPE,
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

@app.route('/rsa/intro')
def rsa_intro() -> None:
    session["prime_1"] = rsa.get_prime()
    session["prime_2"] = rsa.get_prime()
    return render_template("rsa/introduction.html")

@app.route("/rsa/prime-gen")
def rsa_prime_generation() -> None:
    return render_template("/rsa/key_gen.html", prime_1 = session["prime_1"],
    prime_2 = session["prime_2"])

@app.route("/rsa/message", methods = ["POST", "GET"])
def rsa_message() -> "None":
    if request.method == "POST":
        prime_1 = session["prime_1"]
        prime_2 = session["prime_2"]
        message = request.form["message"]
        encrypted = rsa.encrypt_message(prime_1, prime_2, message)
        session["ciphertext"] = encrypted
        decrypted = rsa.decrypt_message(prime_1, prime_2, encrypted)
        session["plaintext"] = decrypted
        return redirect(url_for("rsa_encrypt_decrypt"))
    else:
        return render_template("/rsa/message.html")

@app.route("/rsa/encryption-decryption")
def rsa_encrypt_decrypt() -> None:
    return render_template("/rsa/encrypt-decrypt.html",
    plaintext = session["plaintext"], ciphertext = session["ciphertext"])