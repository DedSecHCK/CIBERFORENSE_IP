# Ciberforence - README

Este repositorio contiene un conjunto de herramientas para análisis forense pasivo de direcciones IP, enfocado en OSINT, reputación, clasificación y generación de informes periciales. Incluye un motor unificado (`engine_unificado.py`) que centraliza la funcionalidad de varios módulos independientes, así como los módulos utilizados de forma individual.

## Contenido del folder

- `engine_unificado.py`: Motor unificado autocontenible que orquesta todo el análisis y la generación de informe.
- `engine.py`: Versión anterior del motor que utiliza importaciones de los módulos independientes.
- `clasificador_Ip.py`: Clasificación y reputación de IPs (IPinfo + AbuseIPDB).
- `localizador_ip.py`: Geolocalización básica vía IPinfo.
- `lector_diccionario.py`: Carga y consulta de diccionario local de IPs.
- `generar_informe.py`: Generación de informe pericial en formato DOCX.
- `diccionario_ips.json`: Diccionario local de IPs, categorías o notas específicas.
- `asn_ecuador.json`: Mapa de ASN de Ecuador (por ejemplo: {"AS12345":"Nombre ISP"}).

## Requisitos

- Python 3.8 o superior.
- Paquetes:
  - `requests`
  - `python-docx` (opcional; solo para generar DOCX. El motor unificado continúa sin esta librería)
- Conectividad a Internet para consultas OSINT (IPinfo y AbuseIPDB).
- Claves/Token:
  - Clave API de AbuseIPDB (`--abuse`).
  - Token de IPinfo (`--token`) opcional; mejora la estabilidad y el límite de consultas.

Instalación de paquetes en Windows:
- py -m pip install requests
- py -m pip install python-docx

Verificar instalación:
- py -m pip show requests
- py -m pip show python-docx

## Uso recomendado: engine_unificado.py

El motor unificado centraliza:
- Geolocalización OSINT (IPinfo).
- Reputación y clasificación (AbuseIPDB + heurísticas de ASN/organización).
- Consulta de diccionario local (`diccionario_ips.json`).
- Generación de informe pericial DOCX (si está instalada `python-docx`).
- Salida consolidada en JSON.

Ejemplo de ejecución:
- python3 engine_unificado.py ips.txt --caso 2025-045 --cliente "Empresa S.A." --contrato "789" --abuse TU_ABUSE_KEY --token TU_IPINFO_TOKEN

Parámetros:
- `archivo_ips`: Ruta al archivo de texto con una IP por línea.
- `--abuse`: Clave API de AbuseIPDB (obligatoria).
- `--token`: Token de IPinfo (opcional).
- `--caso`: Número de caso (obligatorio).
- `--cliente`: Cliente o entidad solicitante (obligatorio).
- `--contrato`: Número de contrato/autorización (obligatorio).
- `--dic`: Ruta opcional al diccionario local JSON. Por defecto usa `diccionario_ips.json`.

Archivos generados:
- `resultado_unificado.json`: Lista de objetos por IP, incluyendo geolocalización, clasificación y categoría local.
- `resultados_ips.json`: Lista “plana” con los resultados del clasificador (consumido por el generador de informe).
- `informe_fiscalia_<caso>.docx`: Informe pericial. Solo se genera si `python-docx` está disponible.

Notas:
- Si `python-docx` no está instalado, el motor mostrará un mensaje y continuará sin generar el DOCX. Los JSON se generan igual.
- Asegúrate de que `diccionario_ips.json` y `asn_ecuador.json` estén ubicados en el mismo directorio de ejecución.

## Módulos individuales

Puedes usar los módulos por separado si lo prefieres o para pruebas unitarias.

### 1) clasificador_Ip.py
Funcionalidad:
- Consulta IPinfo para obtener organización, país y ASN.
- Consulta AbuseIPDB para obtener `abuseConfidenceScore`.
- Aplica heurísticas para clasificar la IP:
  - Atacante internacional
  - VPS en Ecuador (posible atacante real)
  - IP con alta reputación maliciosa (posible botnet)
  - Dispositivo doméstico infectado (víctima)

Entrada:
- Archivo de IPs (una por línea).
- Clave de AbuseIPDB (obligatoria).
- Token de IPinfo (opcional).

Uso:
- python3 clasificador_Ip.py ips.txt TU_ABUSE_KEY [IPINFO_TOKEN]

Salida:
- `resultados_ips.json`: Lista de resultados por IP con campos como `pais`, `isp`, `asn`, `abuse_score`, `clasificacion`.

Dependencias:
- `requests`
- `asn_ecuador.json` (en el mismo directorio), si quieres mapear ASNs a ISP locales.

### 2) localizador_ip.py
Funcionalidad:
- Geolocaliza una IP vía IPinfo y devuelve un diccionario con `pais`, `region`, `ciudad`, `org`, `loc`.

Uso sencillo en Python:
- from localizador_ip import localizar_ip
- localizar_ip("8.8.8.8")

Dependencias:
- `requests`

Nota:
- Para gran volumen o mayor estabilidad, usa un token de IPinfo en el motor unificado. Este módulo por sí solo no añade el token.

### 3) lector_diccionario.py
Funcionalidad:
- Carga `diccionario_ips.json` y permite consultar si una IP está en el diccionario y obtener su categoría/nota.

Estructura esperada (`diccionario_ips.json`):
- {
  "1.2.3.4": "Botnet conocida",
  "5.6.7.8": "IP del cliente - whitelisted"
}

Uso:
- from lector_diccionario import cargar_diccionario, ip_en_diccionario
- dic = cargar_diccionario()
- ip_en_diccionario("1.2.3.4", dic)

Dependencias:
- Ninguna adicional (usa estándar `json` y `os`).

### 4) generar_informe.py
Funcionalidad:
- Genera un informe DOCX a partir de un archivo de resultados JSON producido por el clasificador:
  - Encabezados, datos del caso, metodología, hallazgos por IP y conclusiones.
- Espera una lista de objetos con los campos:
  - `ip`, `pais`, `isp`, `abuse_score`, `clasificacion`

Uso:
- python3 generar_informe.py <caso> <cliente> <resultados.json> <contrato>

Dependencias:
- `python-docx`

Recomendación:
- Usar `resultados_ips.json` producido por `clasificador_Ip.py` o por `engine_unificado.py`.

## Estructura de datos de salida

`resultado_unificado.json` (motor unificado):
- [
  {
    "ip": "8.8.8.8",
    "localizacion": {
      "ip": "8.8.8.8",
      "pais": "US",
      "region": "...",
      "ciudad": "...",
      "org": "AS15169 Google LLC",
      "loc": "lat,long"
    },
    "clasificacion_forense": {
      "ip": "8.8.8.8",
      "pais": "US",
      "isp": "AS15169 Google LLC",
      "asn": "AS15169",
      "isp_ecuador": null,
      "es_datacenter": false,
      "abuse_score": 0,
      "clasificacion": "Atacante internacional"
    },
    "categoria_local": null,
    "timestamp": "2025-01-01T00:00:00Z"
  }
]

`resultados_ips.json` (para informe):
- [
  {
    "ip": "8.8.8.8",
    "pais": "US",
    "isp": "AS15169 Google LLC",
    "asn": "AS15169",
    "isp_ecuador": null,
    "es_datacenter": false,
    "abuse_score": 0,
    "clasificacion": "Atacante internacional"
  }
]

## Buenas prácticas y recomendaciones

- Mantén tus claves y tokens fuera del código fuente; utiliza variables de entorno o parámetros CLI.
- Respeta los Términos de Uso y límites de API de IPinfo y AbuseIPDB.
- No realices escaneos activos; estas herramientas están diseñadas para análisis pasivo.
- Documenta tus hallazgos y guarda los JSON generados como evidencia técnica.
- Verifica que el archivo `asn_ecuador.json` esté actualizado para mejorar la precisión de la clasificación local.

## Solución de problemas

- Error “No module named 'docx'”:
  - Instala: py -m pip install python-docx
  - Si no lo instalas, `engine_unificado.py` continuará sin generar DOCX, pero sí los JSON.
- Error de conexión a IPinfo o AbuseIPDB:
  - Verifica conectividad y tokens/claves válidas.
  - Asegúrate de no sobrepasar límites de consultas.
- Archivo `diccionario_ips.json` no encontrado:
  - Crea el archivo, aunque sea vacío (`{}`), o indica ruta con `--dic`.

## Licencia y uso

Este conjunto de herramientas está orientado a fines forenses y educativos. El uso debe estar autorizado por el cliente y cumplir con las leyes locales aplicables (por ejemplo, COIP en Ecuador para el marco legal referenciado en el informe).
