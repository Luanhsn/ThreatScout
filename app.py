from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
from urllib.parse import urlparse
import requests
import os
import ipaddress
import socket

app = Flask(__name__)
load_dotenv()

abuseipid_key = os.getenv("ABUSEIPDB_KEY")
otx_key = os.getenv("OTX_KEY")
virustotal_key = os.getenv("VIRUSTOTAL_KEY")


def get_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": abuseipid_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
    print(response.json())
    return response.json()

def get_alienvault(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": otx_key}
    response = requests.get(url, headers=headers)
    return response.json()

def get_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": virustotal_key}
    response = requests.get(url, headers=headers)
    return response.json()

def get_alienvault_domain(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": otx_key}
    response = requests.get(url, headers=headers)
    return response.json()

def get_virustotal_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": virustotal_key}
    response = requests.get(url, headers=headers)
    return response.json()

def calculate_score(abuse_data, otx_data, vt_data):
    abuseipdb_score = abuse_data["data"]["abuseConfidenceScore"]
    alienvault_score = min(otx_data["pulse_info"]["count"] * 10, 100)
    virustotal_score = min(vt_data["data"]["attributes"]["last_analysis_stats"]["malicious"] * 5, 100)

    score = (abuseipdb_score + alienvault_score + virustotal_score) / 3
    return score

def detect_input_type(value):
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if value.startswith("http://") or value.startswith("https://"):
        return "url"

    return "domain"


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check")
def check():
    value = request.args.get("query")
    if not value:
        return jsonify({"error": "Keine Eingabe"}), 400

    input_type = detect_input_type(value)

    if input_type == "url":
        value = urlparse(value).hostname

    if input_type == "ip":
        abuse_data = get_abuseipdb(value)
        otx_data = get_alienvault(value)
        vt_data = get_virustotal(value)
    else:
        print("domain:", value)
        ip = resolve_domain(value)
        abuse_data = get_abuseipdb(ip)
        otx_data = get_alienvault_domain(value)
        vt_data = get_virustotal_domain(value)

    score = calculate_score(abuse_data, otx_data, vt_data)

    return jsonify({
        "ip": ip,
        "score": score,
        "abuseipdb": abuse_data["data"]["abuseConfidenceScore"],
        "alienvault": otx_data["pulse_info"]["count"],
        "virustotal": vt_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
    })


if __name__ == "__main__":
    app.run(debug=True, port=5001)
