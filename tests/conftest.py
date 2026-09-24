"""Fixtures compartidas para la suite de tests de recon-ai-suite."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SAMPLE_TARGET = "192.168.56.10"


@pytest.fixture
def fixtures_dir() -> Path:
    """Directorio con los ficheros de evidencia sintética."""
    return FIXTURES_DIR


@pytest.fixture
def nmap_xml_path() -> Path:
    """Ruta al XML de nmap realista multi-host."""
    return FIXTURES_DIR / "sample_nmap.xml"


@pytest.fixture
def gobuster_txt_path() -> Path:
    """Ruta a la salida típica (modo -q) de gobuster."""
    return FIXTURES_DIR / "sample_gobuster.txt"


@pytest.fixture
def sample_hosts(nmap_xml_path: Path) -> list[dict]:
    """Hosts ya normalizados a partir del XML de nmap."""
    from src import parser

    return parser.parse_nmap_xml(nmap_xml_path)


@pytest.fixture
def sample_web_paths(gobuster_txt_path: Path) -> list[dict]:
    """Rutas web ya normalizadas a partir del TXT de gobuster."""
    from src import parser

    return parser.parse_gobuster_txt(gobuster_txt_path)


@pytest.fixture
def tmp_config(tmp_path: Path) -> dict:
    """Config mínima con salida en un directorio temporal (vacío)."""
    return {
        "project": {
            "name": "recon-ai-suite",
            "output_dir": str(tmp_path / "evidencia"),
            "timezone": "UTC",
        }
    }


@pytest.fixture
def config_with_fixtures(tmp_path: Path, nmap_xml_path: Path, gobuster_txt_path: Path) -> dict:
    """Config cuya carpeta raw contiene la evidencia sintética del target."""
    base = tmp_path / "evidencia"
    raw = base / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(nmap_xml_path, raw / f"nmap_{SAMPLE_TARGET}.xml")
    shutil.copyfile(gobuster_txt_path, raw / f"gobuster_{SAMPLE_TARGET}.txt")
    return {"project": {"output_dir": str(base)}}


@pytest.fixture
def config_file(tmp_path: Path, config_with_fixtures: dict) -> Path:
    """Escribe la config anterior en disco para probar el CLI ``main``."""
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config_with_fixtures), encoding="utf-8")
    return path
