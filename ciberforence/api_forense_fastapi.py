import json
import os
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from clasificador_Ip import clasificar_ip
from generar_informe import generar_informe

app = FastAPI(title="API Forense Pasiva", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    ips: List[str] = Field(..., description="Lista de direcciones IP a analizar")
    abuse_key: str = Field(..., description="API Key de AbuseIPDB")
    ipinfo_token: Optional[str] = Field(None, description="Token opcional de IPinfo")


class ReportRequest(BaseModel):
    caso: str
    cliente: str
    contrato: str
    resultados: Optional[List[dict]] = None


@app.get("/health")
def health_check():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    """Analiza una lista de IPs (pasivo) y devuelve resultados."""
    if not req.ips:
        raise HTTPException(status_code=400, detail="Se requieren IPs para analizar")

    resultados = []
    for ip in req.ips:
        try:
            res = clasificar_ip(ip.strip(), req.abuse_key, req.ipinfo_token)
            resultados.append(res)
        except Exception as e:
            resultados.append({"ip": ip, "error": str(e)})

    # Guardar resultados en disco para compatibilidad con la función de generación de informes
    output_file = "resultados_ips.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(resultados, f, indent=2, ensure_ascii=False)

    return {
        "status": "ok",
        "file": output_file,
        "count": len(resultados),
        "resultados": resultados,
    }


@app.post("/report")
def create_report(req: ReportRequest):
    """Genera informe DOCX a partir de resultados en la request o del archivo en disco."""
    resultados_file = "resultados_ips.json"
    if req.resultados:
        with open(resultados_file, "w", encoding="utf-8") as f:
            json.dump(req.resultados, f, indent=2, ensure_ascii=False)
    else:
        if not os.path.exists(resultados_file):
            raise HTTPException(
                status_code=400,
                detail=(
                    "No se enviaron resultados en la petición y no existe 'resultados_ips.json' en disco."
                ),
            )

    try:
        generar_informe(req.caso, req.cliente, resultados_file, req.contrato)
    except SystemExit:
        # generar_informe usa sys.exit en errores; atrapamos y convertimos en 500
        raise HTTPException(
            status_code=500, detail="Error al generar el informe (revisa logs)"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    nombre_doc = f"informe_fiscalia_{req.caso.replace('/', '_')}.docx"
    if not os.path.exists(nombre_doc):
        raise HTTPException(
            status_code=500, detail="Informe no fue generado (archivo faltante)"
        )

    return {"status": "ok", "informe": nombre_doc}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api_forense_fastapi:app", host="0.0.0.0", port=8000, reload=True)
