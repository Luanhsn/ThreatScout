from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
import requests
import os

app = Flask(__name__)
load_dotenv()

abuseipid_api = os.getenv("ABUSEIPDB_KEY")
otx_key = os.getenv("OTX_KEY")
virustotal_key = os.getenv("VIRUSTOTAL_KEY")


def get_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": abuseipid_api, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
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

def calculate_score(abuse_data, otx_data, vt_data):
    abuseipdb_score = abuse_data["data"]["abuseConfidenceScore"]
    alienvault_score = min(otx_data["pulse_info"]["count"] * 10, 100)
    virustotal_score = min(vt_data["data"]["attributes"]["last_analysis_stats"]["malicious"] * 5, 100)

    score = (abuseipdb_score + alienvault_score + virustotal_score) / 3
    return score

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/check")
def check():
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "Keine IP angegeben"}), 400

    abuse_data = get_abuseipdb(ip)
    otx_data = get_alienvault(ip)
    vt_data = get_virustotal(ip)
    score = calculate_score(abuse_data, otx_data, vt_data)

    return jsonify({
        "ip": ip,
        "score": score,
        "abuseipdb": abuse_data,
        "alienvault": otx_data,
        "virustotal": vt_data
    })


if __name__ == "__main__":
    app.run(debug=True)
