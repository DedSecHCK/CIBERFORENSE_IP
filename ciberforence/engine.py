#!/usr/bin/env python3
"""
ENGINE UNIFICADO FORENSE PASIVO (DedSec Edition)
------------------------------------------------
Este motor centraliza:
- Localización OSINT
- Reputación AbuseIPDB
- Clasificación avanzada (VPS, Internacional, Botnet, Hogar)
- Diccionario local (rangos, ASN, listas negras)
- Generación de informe pericial

Modo de uso:
    python3 engine_unificado.py ips.txt --caso 2025-045 --cliente "Empresa S.A." --contrato "789" --abuse CLAVE --token TOKEN

Requiere:
- clasificador_Ip.py
- localizador_ip.py
- lector_diccionario.py
- generar_informe.py
- diccionario_ips.json
- asn_ecuador.json
"""

import argparse
import json
import os
from datetime import datetime

# Clasificación y reputación
from clasificador_Ip import clasificar_ip  # usa tu archivo clasificador_Ip.py
from generar_informe import generar_informe  # usa tu archivo generar_informe.py
from lector_diccionario import cargar_diccionario, ip_en_diccionario

# Importación desde la misma carpeta ciberforense
# Localización OSINT
from localizador_ip import localizar_ip  # <- agregado


def analizar_ips(ips, abuse_key, ipinfo_token=None):
    dic = cargar_diccionario()
    resultados = []

    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue

        print(f"\n🔍 Analizando {ip}…")

        # OSINT: Geolocalización (localizador A)
        localizacion = localizar_ip(ip)
        localizacion = localizar_ip(ip)

        # Reputación global
        rep = clasificar_ip(ip, abuse_key, ipinfo_token)

        # Clasificación local forense
        categoria_local = ip_en_diccionario(ip, dic)

        fusion = {
            "ip": ip,
            "localizacion": localizacion,
            "clasificacion_forense": rep,
            "categoria_local": categoria_local,
            "timestamp": datetime.utcnow().isoformat(),
        }

        resultados.append(fusion)

    with open("resultado_unificado.json", "w", encoding="utf-8") as f:
        json.dump(resultados, f, indent=2, ensure_ascii=False)

    print("resultado_unificado.json generado")
    return resultados


def main():
    parser = argparse.ArgumentParser(
        description="Motor unificado de análisis pasivo de IPs"
    )
    parser.add_argument("archivo_ips", help="Archivo con lista de IPs")
    parser.add_argument("--abuse", required=True, help="API Key de AbuseIPDB")
    parser.add_argument("--token", required=False, help="Token de IPinfo")
    parser.add_argument("--caso", required=True, help="Número de caso para informe")
    parser.add_argument(
        "--cliente", required=True, help="Cliente o entidad solicitante"
    )
    parser.add_argument("--contrato", required=True, help="Contrato/autorización")

    args = parser.parse_args()

    if not os.path.exists(args.archivo_ips):
        print(f"No existe el archivo {args.archivo_ips}")
        return

    with open(args.archivo_ips, "r") as f:
        ips = [line.strip() for line in f.readlines() if line.strip()]

    print(f"Iniciando análisis de {len(ips)} IPs")

    analizar_ips(ips, args.abuse, args.token)

    print("Generando informe DOCX…")
    generar_informe(
        args.caso,
        args.cliente,
        "resultado_unificado.json",
        args.contrato,
    )

    print("Proceso finalizado. Informe listo.")


if __name__ == "__main__":
    main()
