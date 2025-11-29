#!/usr/bin/env python3

import os

ips_ejemplo = """203.0.113.45
198.51.100.22
186.78.123.45
181.192.45.67
200.87.123.45
"""

with open("ips_objetivo.txt", "w") as f:
    f.write(ips_ejemplo)

print("Paso 1: Archivo ips_objetivo.txt creado")

abuse_key = input("Ingresa tu API Key de AbuseIPDB: ").strip()
if not abuse_key:
    print(
        "❌ Se requiere una API Key de AbuseIPDB. Regístrate en https://www.abuseipdb.com/"
    )
    exit(1)

ipinfo_token = input("(Opcional) Token de IPinfo (Enter para omitir): ").strip()

print("Paso 2: Analizando IPs (consultas pasivas)...")
cmd = f"python3 01_clasificador_ips.py ips_objetivo.txt {abuse_key}"
if ipinfo_token:
    cmd += f" {ipinfo_token}"
os.system(cmd)

print("Paso 3: Generando informe para la Fiscalía...")
os.system(
    'python3 02_generar_informe.py "2025-045" "Empresa Cliente S.A." "resultados_ips.json" "Contrato N°789"'
)

print("¡Análisis completado! Revisa los archivos generados.")
