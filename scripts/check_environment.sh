#!/usr/bin/env bash
# =============================================================================
# recon-ai-suite - Verificación del entorno antes de un reconocimiento real
# -----------------------------------------------------------------------------
# Uso:
#   ./scripts/check_environment.sh
#
# Comprueba: nmap, gobuster, Python >= 3.10, DEEPSEEK_API_KEY (sin imprimirla)
# y la wordlist de gobuster declarada en config.yaml.
# Devuelve exit code 1 si algún check falla.
# =============================================================================
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${PROJECT_ROOT}/config.yaml"
FAILED=0

ok()  { echo "✅ $1"; }
bad() { echo "❌ $1"; FAILED=$((FAILED + 1)); }

echo "=============================================================="
echo " recon-ai-suite | verificación de entorno"
echo " proyecto: ${PROJECT_ROOT}"
echo "=============================================================="

# --- 1) nmap -----------------------------------------------------------------
if command -v nmap >/dev/null 2>&1; then
  ok "nmap instalado -> $(nmap --version 2>/dev/null | head -n1)"
else
  bad "nmap NO encontrado en el PATH (https://nmap.org/download.html)"
fi

# --- 2) gobuster -------------------------------------------------------------
if command -v gobuster >/dev/null 2>&1; then
  ok "gobuster instalado -> $(gobuster --version 2>&1 | head -n1)"
else
  bad "gobuster NO encontrado en el PATH (https://github.com/OJ/gobuster)"
fi

# --- 3) Python >= 3.10 -------------------------------------------------------
PY="$(command -v python3 || command -v python || true)"
if [[ -n "${PY}" ]]; then
  PY_VERSION="$("${PY}" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || echo "?")"
  if "${PY}" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 10) else 1)' 2>/dev/null; then
    ok "Python ${PY_VERSION} (>= 3.10) en ${PY}"
  else
    bad "Python ${PY_VERSION} es menor que 3.10 (${PY})"
  fi
else
  bad "Python NO encontrado en el PATH (se requiere >= 3.10)"
fi

# --- 4) DEEPSEEK_API_KEY (nunca se imprime su valor) -------------------------
if [[ -n "${DEEPSEEK_API_KEY:-}" ]]; then
  ok "DEEPSEEK_API_KEY definida (longitud: ${#DEEPSEEK_API_KEY} caracteres)"
else
  bad "DEEPSEEK_API_KEY no definida -> el priorizador usará la heurística local"
fi

# --- 5) Wordlist de gobuster declarada en config.yaml ------------------------
WL=""
if [[ -n "${PY}" && -f "${CONFIG}" ]]; then
  WL="$("${PY}" -c "import yaml, sys; print(yaml.safe_load(open(sys.argv[1], encoding='utf-8'))['scanner']['gobuster']['wordlist'])" "${CONFIG}" 2>/dev/null || true)"
fi
if [[ -z "${WL}" && -f "${CONFIG}" ]]; then
  # Respaldo sin PyYAML: leer la clave wordlist directamente del YAML.
  WL="$(grep -E '^[[:space:]]*wordlist:' "${CONFIG}" | head -n1 | sed -E 's/^[^:]*:[[:space:]]*//; s/#.*//' | tr -d '[:space:]"' | tr -d "'")"
fi

if [[ -n "${WL}" ]]; then
  WL_ABS="${WL}"
  case "${WL}" in
    /*|[A-Za-z]:[\\/]*) WL_ABS="${WL}" ;;                    # ya es absoluta
    *) WL_ABS="${PROJECT_ROOT}/${WL#./}" ;;                 # relativa al proyecto
  esac
  if [[ -f "${WL_ABS}" ]]; then
    ok "wordlist encontrada: ${WL_ABS} ($(wc -l < "${WL_ABS}" | tr -d ' ') líneas)"
  else
    bad "wordlist NO encontrada -> config.yaml dice '${WL}' (resuelto: ${WL_ABS})"
  fi
else
  bad "no se pudo leer scanner.gobuster.wordlist desde ${CONFIG}"
fi

# --- Resumen -----------------------------------------------------------------
echo "--------------------------------------------------------------"
TOTAL=5
if [[ ${FAILED} -eq 0 ]]; then
  echo "RESUMEN: entorno listo (${TOTAL}/${TOTAL} checks OK)"
  exit 0
fi
echo "RESUMEN: $((TOTAL - FAILED))/${TOTAL} checks OK | ${FAILED} con problemas (ver arriba)"
exit 1
