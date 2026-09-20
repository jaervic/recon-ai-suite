#!/usr/bin/env bash
# =============================================================================
# recon-ai-suite - Script de entrada del pipeline completo
# -----------------------------------------------------------------------------
# Uso:
#   ./scripts/run_recon.sh <target> [--tools nmap,gobuster] [--no-ai]
# Ejemplo:
#   ./scripts/run_recon.sh scanme.nmap.org --tools nmap
#
# SECUENCIA: scanner -> parser -> ai_prioritizer -> report_generator
# =============================================================================
set -euo pipefail

TARGET="${1:-}"
if [[ -z "${TARGET}" ]]; then
  echo "Uso: $0 <target> [--tools nmap,gobuster] [--no-ai]" >&2
  exit 1
fi
shift || true

TOOLS="nmap"
AI_FLAG=""
EXTRA_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tools) TOOLS="$2"; shift 2 ;;
    --no-ai) AI_FLAG="--no-ai"; shift ;;
    *) EXTRA_ARGS+=("$1"); shift ;;
  esac
done

# Raíz del proyecto (scripts/ está un nivel por debajo)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

# 1) Entorno virtual (si existe) e interpretador de Python
if [[ -d ".venv" ]]; then
  # shellcheck disable=SC1091
  source .venv/Scripts/activate 2>/dev/null || source .venv/bin/activate
fi

PYTHON="${PYTHON:-python3}"
command -v "${PYTHON}" >/dev/null 2>&1 || PYTHON="python"

if [[ -z "${DEEPSEEK_API_KEY:-}" ]]; then
  echo "[!] DEEPSEEK_API_KEY no definida: la priorización usará la heurística local."
fi

echo "=============================================================="
echo " recon-ai-suite | objetivo: ${TARGET} | herramientas: ${TOOLS}"
echo "=============================================================="

# 2) Fase 1: reconocimiento activo
SCAN_ARGS=(--target "${TARGET}" --tools "${TOOLS}")
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
  SCAN_ARGS+=("${EXTRA_ARGS[@]}")
fi
"${PYTHON}" -m src.scanner "${SCAN_ARGS[@]}"

# 3) Fase 2: parseo a JSON estructurado
"${PYTHON}" -m src.parser --target "${TARGET}"

# 4) Fase 3: priorización con IA (DeepSeek) o heurística
# shellcheck disable=SC2086
"${PYTHON}" -m src.ai_prioritizer --target "${TARGET}" ${AI_FLAG}

# 5) Fase 4: informe Markdown
"${PYTHON}" -m src.report_generator --target "${TARGET}"

echo "[ok] Pipeline completado. Informe en: evidencia/reportes/"
