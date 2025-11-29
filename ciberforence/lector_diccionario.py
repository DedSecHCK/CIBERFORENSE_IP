#!/usr/bin/env python3

import json
import os

DICCIONARIO_PATH = "diccionario_ips.json"


def cargar_diccionario(path=DICCIONARIO_PATH):
    """
    Carga el diccionario local de IPs desde un archivo JSON.
    Si el archivo no existe, retorna un diccionario vacío.
    """
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return {}


def ip_en_diccionario(ip, diccionario):
    """
    Consulta si una IP está en el diccionario y retorna su categoría o información asociada.
    Si no está, retorna None.
    """
    return diccionario.get(ip, None)


if __name__ == "__main__":
    # Ejemplo de uso
    dic = cargar_diccionario()
    test_ip = "8.8.8.8"
    info = ip_en_diccionario(test_ip, dic)
    if info:
        print(f"La IP {test_ip} está en el diccionario: {info}")
    else:
        print(f"La IP {test_ip} no está en el diccionario.")
