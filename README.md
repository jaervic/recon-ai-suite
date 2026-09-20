# 🤖 recon-ai-suite

![Estado](https://img.shields.io/badge/estado-en%20progreso-yellow)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![IA](https://img.shields.io/badge/LLM-DeepSeek-purple)
![Uso](https://img.shields.io/badge/uso-pentest%20autorizado-red)

Pipeline de **reconocimiento automatizado asistido por IA**: envuelve herramientas
ofensivas (nmap, gobuster), normaliza su salida a JSON, la prioriza con un LLM
(DeepSeek) y genera un informe Markdown listo para el cliente.

> ⚠️ **Uso ético y legal**: úsalo únicamente contra sistemas propios o con
> autorización escrita (alcance de pentest). El escaneo no autorizado es ilegal.

## 🏗️ Arquitectura

```
┌─────────┐   ┌─────────┐   ┌────────────────┐   ┌──────────────────┐
│ scanner │──▶│ parser  │──▶│ ai_prioritizer │──▶│ report_generator │
│ (nmap,  │   │ (XML -> │   │ (DeepSeek API  │   │ (Markdown ->     │
│ gobuster)│   │  JSON)  │   │  o heurística) │   │  informe .md)    │
└─────────┘   └─────────┘   └────────────────┘   └──────────────────┘
     │             │                 │                     │
 evidencia/raw  evidencia/parsed  evidencia/parsed   evidencia/reportes
```

Detalle completo en [`docs/01-arquitectura.md`](docs/01-arquitectura.md) y
metodología en [`docs/02-metodologia.md`](docs/02-metodologia.md).

## 📂 Estructura

```
recon-ai-suite/
├── README.md
├── requirements.txt
├── config.yaml              # Configuración: API keys, rutas, etc.
├── src/
│   ├── __init__.py          # Carga de config y rutas compartidas
│   ├── scanner.py           # Envuelve nmap, gobuster, etc.
│   ├── parser.py            # Parsea outputs a JSON estructurado
│   ├── ai_prioritizer.py    # Integra DeepSeek API para priorizar
│   └── report_generator.py  # Genera informe en Markdown
├── scripts/
│   └── run_recon.sh         # Script de entrada
├── docs/
│   ├── 01-arquitectura.md
│   └── 02-metodologia.md
└── evidencia/               # raw/ , parsed/ , reportes/
```

## ⚙️ Instalación

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Herramientas externas (no se instalan con pip)
sudo apt install nmap gobuster   # Kali/Debian
```

Dependencias Python declaradas en `requirements.txt`:

| Paquete | Rol en el pipeline |
|---|---|
| `python-nmap` | Envuelve el binario **nmap** y entrega el XML ya parseado (etapa *Nmap Scan*) |
| `openai` | Cliente del LLM, compatible con la API de DeepSeek (etapa *DeepSeek API*) |
| `requests` | Transporte HTTP de respaldo si el SDK `openai` no está instalado |
| `PyYAML` | Lectura de `config.yaml` (target, flags, modelo, rutas) |
| `Jinja2` | Plantilla del informe (Markdown) |

Configura la API key **como variable de entorno** (nunca en `config.yaml`):

```bash
export DEEPSEEK_API_KEY="sk-..."                 # Linux/WSL/macOS
$env:DEEPSEEK_API_KEY = "sk-..."                 # PowerShell
```

## 🚀 Uso

Pipeline completo con un solo comando:

```bash
./scripts/run_recon.sh scanme.nmap.org --tools nmap
```

O cada fase por separado:

```bash
python -m src.scanner        --target scanme.nmap.org --tools nmap,gobuster
python -m src.parser         --target scanme.nmap.org
python -m src.ai_prioritizer --target scanme.nmap.org          # --no-ai = heurística
python -m src.report_generator --target scanme.nmap.org --out docs/informe.md
```

`ai_prioritizer` degrada con elegancia: si no hay API key o la API falla, aplica
una heurística local de severidad para no romper el pipeline.

## 🔎 Qué produce

| Artefacto | Ruta | Descripción |
|---|---|---|
| Evidencia cruda | `evidencia/raw/` | XML de nmap / texto de gobuster |
| JSON estructurado | `evidencia/parsed/<target>.json` | Hosts, puertos, rutas y hallazgos |
| Priorización | `evidencia/parsed/<target>_priorizado.json` | Severidad + análisis del LLM |
| Informe | `evidencia/reportes/<target>_<fecha>.md` | Documento final entregable |

## 🧠 Campos de la priorización IA

Cada hallazgo se enriquece con: `severity` (crítica/alta/media/baja/informativa),
`explanation` (riesgo real), `recommendation` (remediación) y `mitre_technique`
(ej. `T1046` para *Network Service Discovery*).

## 📚 Referencias

- [Nmap](https://nmap.org/book/man.html) · [Gobuster](https://github.com/OJ/gobuster)
- [DeepSeek API](https://api-docs.deepseek.com/)
- [MITRE ATT&CK](https://attack.mitre.org/)

## 👤 Autor

**Tu Nombre** — LinkedIn: [tu-perfil] · GitHub: [@tu-usuario]
