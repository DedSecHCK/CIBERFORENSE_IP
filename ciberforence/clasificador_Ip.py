#!/usr/bin/env python3

import json
import socket
import sys

import requests

with open("asn_ecuador.json") as f:
    ASN_EC = json.load(f)


def ipinfo_lookup(ip, token=None):
    url = f"https://ipinfo.io/{ip}/json"
    if token:
        url += f"?token={token}"
    try:
        res = requests.get(url, timeout=8)
        return res.json() if res.status_code == 200 else {}
    except Exception as e:
        return {"error": str(e)}


def abuseipdb_lookup(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        res = requests.get(url, headers=headers, params=params, timeout=8)
        data = res.json()
        return data.get("data", {}) if res.status_code == 200 else {}
    except Exception as e:
        return {"error": str(e)}


def clasificar_ip(ip, abuse_key, ipinfo_token=None):
    try:
        socket.inet_aton(ip)
    except Exception:
        return {"ip": ip, "error": "IP inválida"}

    ipinfo = ipinfo_lookup(ip, ipinfo_token)
    abuse = abuseipdb_lookup(ip, abuse_key)

    org = ipinfo.get("org", "N/A")
    country = ipinfo.get("country", "N/A")
    asn_raw = org.split()[0] if org != "N/A" and org.split() else "N/A"

    is_ec = country == "EC"
    isp_ec = ASN_EC.get(asn_raw, None) if is_ec else None

    is_datacenter = False
    if org != "N/A":
        org_low = org.lower()
        datacenter_keywords = [
            "cloud",
            "hosting",
            "vps",
            "digitalocean",
            "aws",
            "hetzner",
            "linode",
            "netlife",
            "fibra",
            "datacenter",
        ]
        if any(kw in org_low for kw in datacenter_keywords):
            is_datacenter = True

    abuse_score = int(abuse.get("abuseConfidenceScore", 0))

    if not is_ec:
        conclusion = "Atacante internacional"
    elif is_datacenter:
        conclusion = "VPS en Ecuador (posible atacante real)"
    elif abuse_score > 60:
        conclusion = "IP con alta reputación maliciosa (posible botnet)"
    else:
        conclusion = "Dispositivo doméstico infectado (víctima)"

    return {
        "ip": ip,
        "pais": country,
        "isp": org,
        "asn": asn_raw,
        "isp_ecuador": isp_ec,
        "es_datacenter": is_datacenter,
        "abuse_score": abuse_score,
        "clasificacion": conclusion,
    }


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(
            "Uso: python3 01_clasificador_ips.py <archivo_ips.txt> <ABUSEIPDB_KEY> [IPINFO_TOKEN]"
        )
        print("Ejemplo: python3 01_clasificador_ips.py ips_objetivo.txt TU_CLAVE")
        sys.exit(1)

    ip_file = sys.argv[1]
    abuse_key = sys.argv[2]
    ipinfo_token = sys.argv[3] if len(sys.argv) > 3 else None

    resultados = []
    with open(ip_file, "r") as f:
        for line in f:
            ip = line.strip()
            if ip and not ip.startswith("#") and not ip.startswith("//"):
                print(f"[+] Analizando {ip}")
                res = clasificar_ip(ip, abuse_key, ipinfo_token)
                resultados.append(res)

    output_file = "resultados_ips.json"
    with open(output_file, "w") as out:
        json.dump(resultados, out, indent=2, ensure_ascii=False)

    print(f" Resultados guardados en {output_file}")
