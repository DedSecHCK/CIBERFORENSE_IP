#!/usr/bin/env python3

import requests


def localizar_ip(ip):
    """
    Función básica de geolocalización de IP.
    Devuelve un diccionario con información de país, región y ciudad.
    Si falla la consulta, retorna valores por defecto.
    """
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                "ip": ip,
                "pais": data.get("country", "N/A"),
                "region": data.get("region", "N/A"),
                "ciudad": data.get("city", "N/A"),
                "org": data.get("org", "N/A"),
                "loc": data.get("loc", "N/A"),
            }
    except Exception:
        pass
    # Si falla, retorna valores dummy
    return {
        "ip": ip,
        "pais": "N/A",
        "region": "N/A",
        "ciudad": "N/A",
        "org": "N/A",
        "loc": "N/A",
    }
