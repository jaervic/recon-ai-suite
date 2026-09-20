"""recon-ai-suite: pipeline de reconocimiento asistido por IA.

Flujo de ejecución:
    scanner -> parser -> ai_prioritizer -> report_generator

Todos los módulos comparten la configuración de ``config.yaml`` y escriben
sus artefactos dentro de ``evidencia/``.
"""

from __future__ import annotations

from pathlib import Path

import yaml

__version__ = "0.1.0"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / "config.yaml"

__all__ = [
    "PROJECT_ROOT",
    "DEFAULT_CONFIG",
    "load_config",
    "paths_from_config",
    "ensure_dir",
]


def load_config(path: str | Path | None = None) -> dict:
    """Carga ``config.yaml`` y devuelve un diccionario.

    Args:
        path: ruta alternativa al archivo de configuración.

    Raises:
        FileNotFoundError: si el archivo indicado no existe.
    """
    config_path = Path(path) if path else DEFAULT_CONFIG
    if not config_path.exists():
        raise FileNotFoundError(f"No se encontró el archivo de configuración: {config_path}")
    with config_path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def paths_from_config(config: dict) -> dict[str, Path]:
    """Resuelve las rutas de salida declaradas en ``config.yaml``.

    Devuelve un diccionario con las claves ``base``, ``raw``, ``parsed`` y
    ``reports`` (todas absolutas y relativas a la raíz del proyecto).
    """
    project = config.get("project", {}) or {}
    base = Path(project.get("output_dir", "evidencia"))
    if not base.is_absolute():
        base = PROJECT_ROOT / base
    return {
        "base": base,
        "raw": base / "raw",
        "parsed": base / "parsed",
        "reports": base / "reportes",
    }


def ensure_dir(path: str | Path) -> Path:
    """Crea el directorio (incluidos sus padres) si no existe y lo devuelve."""
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory
