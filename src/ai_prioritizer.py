"""Integra la API de DeepSeek para priorizar los hallazgos del reconocimiento.

Toma ``evidencia/parsed/<target>.json``, pide al LLM una priorización
razonada y escribe ``evidencia/parsed/<target>_priorizado.json``.
Si no hay API key o la llamada falla, aplica un *fallback* heurístico local
para que el pipeline nunca se detenga.

Uso:
    python -m src.ai_prioritizer --target scanme.nmap.org
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import requests

from . import ensure_dir, load_config, paths_from_config

try:  # SDK oficial: cliente compatible con la API de DeepSeek
    from openai import OpenAI, OpenAIError
except ImportError:  # pragma: no cover - depende del entorno
    OpenAI = None  # type: ignore[assignment]
    OpenAIError = None  # type: ignore[assignment]

ORDER = {"critica": 0, "alta": 1, "media": 2, "baja": 3, "informativa": 4}
SYSTEM_PROMPT = (
    "Eres un analista senior de ciberseguridad ofensiva. Priorizas hallazgos de "
    "reconocimiento para un pentest autorizado. Respondes SIEMPRE con JSON válido, "
    "sin texto adicional ni bloques de código."
)


def _severity_of(finding: dict) -> str:
    """Normaliza la severidad de un hallazgo (sin acentos, en minúsculas)."""
    value = str(finding.get("severity") or finding.get("severity_hint") or "media").lower()
    value = value.replace("í", "i").replace("á", "a").replace("ó", "o").replace("é", "e")
    value = {
        "critical": "critica",
        "high": "alta",
        "medium": "media",
        "low": "baja",
        "info": "informativa",
        "informational": "informativa",
    }.get(value, value)
    return value if value in ORDER else "media"


def heuristic_prioritization(document: dict) -> dict:
    """Fallback local: ordena por severidad sugerida del parser."""
    findings = []
    for finding in document.get("findings", []):
        enriched = dict(finding)
        enriched["severity"] = _severity_of(finding)
        enriched["explanation"] = "Priorizado localmente (sin LLM disponible)."
        findings.append(enriched)

    findings.sort(key=lambda item: ORDER.get(item["severity"], 5))
    return {
        "engine": "heuristic",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "executive_summary": (
            f"Se identificaron {len(document.get('hosts', []))} host(s) activo(s) y "
            f"{document.get('summary', {}).get('open_ports', 0)} puerto(s) abierto(s). "
            "Priorización generada sin IA: revisar primero las severidades altas y críticas."
        ),
        "findings": findings,
        "next_steps": [
            "Validar manualmente cada servicio expuesto antes de intentar explotación.",
            "Correlacionar los puertos abiertos con el inventario autorizado del cliente.",
            "Configurar la API key de DeepSeek para obtener priorización razonada por LLM.",
        ],
    }


def build_messages(document: dict) -> list[dict]:
    """Construye el prompt de priorización a partir de los hallazgos parseados."""
    compact = [
        {
            "id": finding.get("id"),
            "title": finding.get("title"),
            "host": finding.get("host"),
            "evidence": finding.get("evidence"),
            "severity_hint": finding.get("severity_hint"),
            "source": finding.get("source"),
        }
        for finding in document.get("findings", [])
    ]
    user_prompt = (
        "Objetivo del pentest: {target}\n"
        "Resumen del escaneo: {summary}\n\n"
        "Hallazgos (JSON):\n{findings}\n\n"
        "Devuelve un JSON con esta forma exacta:\n"
        "{{\n"
        '  "executive_summary": "3-5 frases para un lector no técnico",\n'
        '  "findings": [\n'
        "    {{\n"
        '      "id": "mismo id recibido",\n'
        '      "severity": "critica|alta|media|baja|informativa",\n'
        '      "explanation": "por qué importa y qué riesgo real implica",\n'
        '      "recommendation": "acción concreta de remediación",\n'
        '      "mitre_technique": "Txxxx o cadena vacía"\n'
        "    }}\n"
        "  ],\n"
        '  "next_steps": ["paso 1", "paso 2", "paso 3"]\n'
        "}}"
    ).format(
        target=document.get("target", "desconocido"),
        summary=json.dumps(document.get("summary", {}), ensure_ascii=False),
        findings=json.dumps(compact, ensure_ascii=False, indent=2),
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]


def call_deepseek(document: dict, config: dict) -> dict:
    """Prioriza los hallazgos con la API de DeepSeek y devuelve el JSON.

    Vía principal: SDK ``openai`` apuntando a ``api.base_url`` (DeepSeek expone
    una API compatible con OpenAI). Si el SDK no está instalado se usa
    ``requests`` como transporte de respaldo: el resultado es idéntico, sólo
    cambia el motor indicado en ``engine``.

    Raises:
        RuntimeError: si falta la API key en el entorno.
        requests.HTTPError: si la API responde con error HTTP.
        openai.OpenAIError: si el SDK falla (red, autenticación, cuota...).
    """
    api = config.get("api", {}) or {}
    env_var = api.get("api_key_env", "DEEPSEEK_API_KEY")
    api_key = os.environ.get(env_var, "").strip()
    if not api_key:
        raise RuntimeError(f"Falta la variable de entorno {env_var}")

    base_url = str(api.get("base_url", "https://api.deepseek.com")).rstrip("/")
    model = api.get("model", "deepseek-chat")
    messages = build_messages(document)

    if OpenAI is not None:
        content = _ask_with_openai_sdk(api_key, base_url, model, messages, api)
        engine = f"llm:openai-sdk:{model}"
    else:
        content = _ask_with_requests(api_key, base_url, model, messages, api)
        engine = f"llm:requests:{model}"

    result = json.loads(content)
    result["engine"] = engine
    result["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return result


def _ask_with_openai_sdk(
    api_key: str, base_url: str, model: str, messages: list[dict], api: dict
) -> str:
    """Llama a ``/chat/completions`` mediante el SDK oficial de OpenAI."""
    client = OpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=float(api.get("timeout", 60)),
    )
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=float(api.get("temperature", 0.2)),
        max_tokens=int(api.get("max_tokens", 2048)),
        response_format={"type": "json_object"},
    )
    return response.choices[0].message.content or ""


def _ask_with_requests(
    api_key: str, base_url: str, model: str, messages: list[dict], api: dict
) -> str:
    """Respaldo HTTP directo cuando el SDK ``openai`` no está disponible."""
    payload = {
        "model": model,
        "messages": messages,
        "temperature": float(api.get("temperature", 0.2)),
        "max_tokens": int(api.get("max_tokens", 2048)),
        "response_format": {"type": "json_object"},
    }
    response = requests.post(
        f"{base_url}/chat/completions",
        json=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        timeout=float(api.get("timeout", 60)),
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


def merge_with_findings(document: dict, ai_result: dict) -> dict:
    """Fusiona las etiquetas del LLM con los hallazgos técnicos originales."""
    by_id = {item.get("id"): item for item in ai_result.get("findings", []) or []}
    merged: list[dict] = []
    for finding in document.get("findings", []):
        enrichment = by_id.get(finding.get("id"), {})
        merged.append(
            {
                **finding,
                "severity": _severity_of(enrichment or finding),
                "explanation": enrichment.get("explanation", ""),
                "mitre_technique": enrichment.get("mitre_technique", ""),
                "recommendation": enrichment.get("recommendation") or finding.get("recommendation", ""),
            }
        )
    merged.sort(key=lambda item: ORDER.get(item["severity"], 5))

    prioritized = {
        "engine": ai_result.get("engine", "heuristic"),
        "generated_at": ai_result.get("generated_at", document.get("generated_at", "")),
        "target": document.get("target", ""),
        "summary": document.get("summary", {}),
        "counts_by_severity": {
            level: sum(1 for item in merged if item["severity"] == level) for level in ORDER
        },
        "executive_summary": ai_result.get("executive_summary", ""),
        "findings": merged,
        # El inventario técnico viaja con el documento para que el informe pueda
        # renderizar las secciones 4 y 5 sin depender de una segunda lectura.
        "hosts": document.get("hosts", []),
        "web_paths": document.get("web_paths", []),
        "next_steps": ai_result.get("next_steps", []),
    }
    return prioritized


def prioritize_target(target: str, config: dict | None = None, use_ai: bool = True) -> dict:
    """Lee el JSON parseado, prioriza con IA (o heurística) y escribe el resultado."""
    config = config if config is not None else load_config()
    paths = paths_from_config(config)
    ensure_dir(paths["parsed"])

    src_file = paths["parsed"] / f"{target.replace('/', '_')}.json"
    if not src_file.exists():
        raise FileNotFoundError(f"Falta {src_file}; ejecuta antes: python -m src.parser --target {target}")
    document = json.loads(src_file.read_text(encoding="utf-8"))

    if use_ai:
        llm_errors: tuple[type[BaseException], ...] = (
            RuntimeError,
            requests.RequestException,
            KeyError,
            json.JSONDecodeError,
        )
        if OpenAIError is not None:
            llm_errors += (OpenAIError,)
        try:
            ai_result = call_deepseek(document, config)
            print(f"[ai_prioritizer] priorización generada con {ai_result['engine']}")
        except llm_errors as error:
            print(f"[ai_prioritizer] IA no disponible ({error}); usando heurística local")
            ai_result = heuristic_prioritization(document)
    else:
        ai_result = heuristic_prioritization(document)

    prioritized = merge_with_findings(document, ai_result)
    out_file = paths["parsed"] / f"{target.replace('/', '_')}_priorizado.json"
    out_file.write_text(json.dumps(prioritized, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[ai_prioritizer] {out_file} ({len(prioritized['findings'])} hallazgo(s))")
    return prioritized


def main(argv: list[str] | None = None) -> int:
    """Punto de entrada CLI de la fase 3."""
    parser = argparse.ArgumentParser(description="Fase 3: priorización de hallazgos con IA")
    parser.add_argument("--target", required=True, help="IP o dominio objetivo")
    parser.add_argument("--config", default=None, help="Ruta alternativa a config.yaml")
    parser.add_argument("--no-ai", action="store_true", help="Forzar la heurística local (sin API)")
    args = parser.parse_args(argv)

    prioritize_target(args.target, load_config(args.config), use_ai=not args.no_ai)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
