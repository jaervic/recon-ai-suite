"""Genera el informe final en Markdown a partir del JSON priorizado usando plantillas Jinja2.

La plantilla está embebida en este módulo (`REPORT_TEMPLATE`) para respetar la
estructura del proyecto; la presentación queda separada de los datos, de modo
que cambiar la plantilla (hoy el único formato implementado es Markdown, salida
`.md`) no obliga a tocar la lógica del pipeline.

Uso:
    python -m src.report_generator --target scanme.nmap.org
    python -m src.report_generator --target scanme.nmap.org --out docs/informe.md
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template

from . import __version__, ensure_dir, load_config, paths_from_config

SEVERITY_BADGE = {
    "critica": "🔴 Crítica",
    "alta": "🟠 Alta",
    "media": "🟡 Media",
    "baja": "🟢 Baja",
    "informativa": "⚪ Informativa",
}

SEVERITY_ORDER = [
    ("critica", "críticos"),
    ("alta", "altos"),
    ("media", "medios"),
    ("baja", "bajos"),
    ("informativa", "informativos"),
]

REPORT_TEMPLATE = Template(
    """# Informe de reconocimiento: `{{ target }}`

- **Herramienta**: {{ project }} v{{ version }}
- **Fecha de generación**: {{ timestamp }}
- **Motor de priorización**: {{ engine }}
- **Clasificación**: Confidencial - uso interno / pentest autorizado

## 1. Resumen ejecutivo

{{ executive_summary }}

## 2. Métricas del escaneo

| Métrica | Valor |
|---|---|
| Hosts activos | {{ summary.hosts_up | default(0) }} |
| Puertos abiertos | {{ summary.open_ports | default(0) }} |
| Rutas web | {{ summary.web_paths | default(0) }} |
{% for level, label in severity_order %}
| Hallazgos {{ label }} | {{ counts.get(level, 0) }} |
{% endfor %}

## 3. Hallazgos priorizados
{% if not findings %}

_Sin hallazgos registrados._
{% endif %}
{% for finding in findings %}

### 3.{{ loop.index }} [{{ severity_badge.get(finding.severity, finding.severity) }}] {{ finding.title }}

- **ID**: `{{ finding.id }}`
- **Host**: {{ finding.host or 'n/d' }}
- **Fuente**: {{ finding.source }}
- **Técnica MITRE ATT&CK**: {{ finding.mitre_technique or 'no aplica' }}
- **Evidencia**: `{{ finding.evidence or 'n/d' }}`
{% if finding.explanation %}
- **Análisis**: {{ finding.explanation }}
{% endif %}
- **Recomendación**: {{ finding.recommendation or 'n/d' }}
{% endfor %}

## 4. Inventario técnico

{% if not host_rows %}
_No se detectaron hosts con puertos abiertos._
{% else %}
| Host | Hostname | SO | Puerto | Proto | Servicio | Producto / Versión |
|---|---|---|---|---|---|---|
{% for row in host_rows %}
| {{ row.host }} | {{ row.hostname }} | {{ row.os }} | {{ row.port }} | {{ row.protocol }} | {{ row.service }} | {{ row.product }} |
{% endfor %}
{% endif %}

## 5. Superficie web descubierta

{% if not web_rows %}
_Sin resultados de enumeración web (gobuster deshabilitado o sin hallazgos)._
{% else %}
| Ruta | Estado HTTP |
|---|---|
{% for row in web_rows %}
| `{{ row.path }}` | {{ row.status }} |
{% endfor %}
{% endif %}

## 6. Próximos pasos

{% for step in next_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}

## 7. Anexo: alcance y consideraciones

Este informe se generó sobre un objetivo dentro de un alcance autorizado. Los resultados deben validarse manualmente antes de reportar falsos positivos y toda la evidencia cruda queda almacenada en `evidencia/raw/`.
""",
    trim_blocks=True,
    lstrip_blocks=True,
)


def _load_prioritized(target: str, config: dict) -> dict:
    """Carga el JSON priorizado, completando el inventario desde el parseado.

    Los documentos priorizados generados por versiones anteriores no incluían
    ``hosts`` ni ``web_paths``; se recuperan del JSON del parser para que las
    secciones de inventario del informe nunca queden vacías por ese motivo.
    """
    paths = paths_from_config(config)
    slug = target.replace("/", "_")
    parsed_file = paths["parsed"] / f"{slug}.json"
    prioritized_file = paths["parsed"] / f"{slug}_priorizado.json"

    parsed = json.loads(parsed_file.read_text(encoding="utf-8")) if parsed_file.exists() else {}

    if prioritized_file.exists():
        document = json.loads(prioritized_file.read_text(encoding="utf-8"))
    elif parsed:
        document = parsed
    else:
        raise FileNotFoundError(
            f"No hay datos para '{target}'. Ejecuta: python -m src.scanner --target {target} "
            f"y después python -m src.parser --target {target}"
        )

    defaults: dict[str, object] = {"hosts": [], "web_paths": [], "summary": {}}
    for field, default in defaults.items():
        if not document.get(field) and parsed.get(field):
            document[field] = parsed[field] or default
    return document


def _host_rows(hosts: list[dict]) -> list[dict]:
    """Aplana hosts y puertos en filas listas para la plantilla."""
    rows: list[dict] = []
    for host in hosts:
        for port in host.get("ports", []):
            product = " ".join(
                part for part in [port.get("product", ""), port.get("version", "")] if part
            )
            rows.append(
                {
                    "host": host.get("ip") or "-",
                    "hostname": host.get("hostname") or "-",
                    "os": host.get("os") or "-",
                    "port": port.get("port"),
                    "protocol": port.get("protocol"),
                    "service": port.get("service") or "-",
                    "product": product or "-",
                }
            )
    return rows


def _web_rows(web_paths: list[dict]) -> list[dict]:
    """Normaliza las rutas web descubiertas para la plantilla."""
    return [
        {"path": entry.get("path", "-"), "status": entry.get("status") or "n/d"}
        for entry in web_paths
    ]


def build_markdown(document: dict, config: dict | None = None) -> str:
    """Renderiza el informe Markdown a partir del documento priorizado.

    Todo el formato vive en ``REPORT_TEMPLATE``; esta función sólo prepara el
    contexto, por lo que cambiar la presentación no requiere tocar la lógica.
    """
    config = config or {}
    return REPORT_TEMPLATE.render(
        project=(config.get("project", {}) or {}).get("name", "recon-ai-suite"),
        version=__version__,
        target=document.get("target", "desconocido"),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        engine=document.get("engine", "heuristic"),
        executive_summary=document.get("executive_summary") or "_Sin resumen ejecutivo._",
        summary=document.get("summary", {}) or {},
        counts=document.get("counts_by_severity", {}) or {},
        severity_order=SEVERITY_ORDER,
        severity_badge=SEVERITY_BADGE,
        findings=document.get("findings", []) or [],
        host_rows=_host_rows(document.get("hosts", []) or []),
        web_rows=_web_rows(document.get("web_paths", []) or []),
        next_steps=document.get("next_steps") or ["Definir próximos pasos con el equipo."],
    )


def generate_report(
    target: str, config: dict | None = None, out_file: str | Path | None = None
) -> Path:
    """Genera el informe, lo escribe en disco y devuelve la ruta final."""
    config = config if config is not None else load_config()
    paths = paths_from_config(config)
    ensure_dir(paths["reports"])

    document = _load_prioritized(target, config)
    content = build_markdown(document, config)

    if out_file:
        destination = Path(out_file)
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        destination = paths["reports"] / f"{target.replace('/', '_')}_{stamp}.md"

    ensure_dir(destination.parent)
    destination.write_text(content, encoding="utf-8")
    print(f"[report_generator] informe -> {destination}")
    return destination


def main(argv: list[str] | None = None) -> int:
    """Punto de entrada CLI de la fase 4."""
    parser = argparse.ArgumentParser(description="Fase 4: generación del informe")
    parser.add_argument("--target", required=True, help="IP o dominio objetivo")
    parser.add_argument("--config", default=None, help="Ruta alternativa a config.yaml")
    parser.add_argument("--out", default=None, help="Ruta de salida personalizada (.md)")
    args = parser.parse_args(argv)

    generate_report(args.target, load_config(args.config), out_file=args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
