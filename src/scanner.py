"""Envuelve herramientas de reconocimiento (nmap, gobuster, etc.).

- **nmap** se ejecuta a través de la librería ``python-nmap``
  (``nmap.PortScanner``), con *fallback* a ``subprocess`` si no está instalada.
- **gobuster** se ejecuta vía ``subprocess`` (herramienta Go sin API Python).

Los flags se leen de ``config.yaml`` y la salida cruda se guarda en
``evidencia/raw/`` para que ``parser.py`` la estructure.

Uso:
    python -m src.scanner --target scanme.nmap.org
    python -m src.scanner --target 192.168.56.10 --tools nmap,gobuster
"""

from __future__ import annotations

import argparse
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import ensure_dir, load_config, paths_from_config

try:  # Vía principal para nmap; subprocess queda como respaldo
    import nmap as python_nmap
except ImportError:  # pragma: no cover - depende del entorno
    python_nmap = None  # type: ignore[assignment]


@dataclass
class ScanResult:
    """Resultado de la ejecución de una herramienta externa."""

    tool: str
    target: str
    command: list[str] = field(default_factory=list)
    exit_code: int = -1
    raw_path: Path | None = None
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        """True si el proceso terminó con código 0."""
        return self.exit_code == 0

    @property
    def command_line(self) -> str:
        """Comando reconstruido y escapado (útil para el informe)."""
        return " ".join(shlex.quote(part) for part in self.command)


class Scanner:
    """Orquestador de las herramientas de reconocimiento."""

    def __init__(self, config: dict, target: str):
        self.config = config
        self.target = target
        self.paths = paths_from_config(config)
        ensure_dir(self.paths["raw"])

    # ------------------------------------------------------------------ utils
    def _slug(self) -> str:
        """Nombre de archivo seguro derivado del objetivo."""
        return self.target.replace("/", "_").replace(":", "_").replace("*", "all")

    def _tool_config(self, tool: str) -> dict:
        return (self.config.get("scanner", {}) or {}).get(tool, {}) or {}

    def is_enabled(self, tool: str) -> bool:
        """Indica si la herramienta está habilitada en ``config.yaml``."""
        return bool(self._tool_config(tool).get("enabled", True))

    def _execute(self, tool: str, command: list[str], timeout: int) -> ScanResult:
        """Lanza el comando, captura stdout/stderr y nunca lanza por exit code."""
        binary = command[0]
        if shutil.which(binary) is None:
            raise RuntimeError(f"'{binary}' no está instalado o no está en el PATH")

        result = ScanResult(tool=tool, target=self.target, command=command)
        print(f"[scanner] ejecutando: {result.command_line}")
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result.exit_code = 124
            result.stderr = f"Timeout de {timeout}s excedido"
            print(f"[scanner] {tool}: {result.stderr}", file=sys.stderr)
            return result

        result.exit_code = completed.returncode
        result.stdout = completed.stdout or ""
        result.stderr = completed.stderr or ""
        if not result.ok:
            print(f"[scanner] {tool} terminó con código {result.exit_code}", file=sys.stderr)
        return result

    # ------------------------------------------------------------- herramientas
    def nmap(self) -> ScanResult:
        """Escaneo de puertos/servicios con salida XML normalizada.

        Vía principal: ``nmap.PortScanner`` (python-nmap), que ejecuta el binario
        y expone el XML con ``get_nmap_last_output()``. Si la librería no está
        instalada se invoca el binario directamente con ``subprocess``.
        """
        cfg = self._tool_config("nmap")
        binary = cfg.get("binary", "nmap")
        flags = shlex.split(cfg.get("flags", "-sV -T4 --top-ports 1000"))
        timeout = int(cfg.get("timeout", 900))
        out_file = self.paths["raw"] / f"nmap_{self._slug()}.xml"

        if python_nmap is None:
            print("[scanner] python-nmap no disponible: se usa subprocess")
            command = [binary, *flags, "-oX", str(out_file), self.target]
            result = self._execute("nmap", command, timeout=timeout)
        else:
            result = self._nmap_with_library(binary, flags, timeout)

        if out_file.exists():
            result.raw_path = out_file
            print(f"[scanner] evidencia cruda -> {out_file}")
        return result

    def _nmap_with_library(self, binary: str, flags: list[str], timeout: int) -> ScanResult:
        """Ejecuta nmap mediante python-nmap y persiste el XML como evidencia.

        Como python-nmap no expone un parámetro de timeout, se refuerza con
        ``--host-timeout`` de nmap usando el valor de ``config.yaml``.
        """
        arguments = " ".join([*flags, f"--host-timeout {timeout}s"])
        result = ScanResult(
            tool="nmap",
            target=self.target,
            command=[binary, *flags, self.target],
        )
        print(f"[scanner] ejecutando (python-nmap): {result.command_line}")

        try:
            scanner = python_nmap.PortScanner()
            scanner.scan(hosts=self.target, arguments=arguments)
            xml_output = scanner.get_nmap_last_output() or ""
            # python-nmap 0.7.1 devuelve bytes en la ruta de scan() (no decodifica
            # el stdout del subproceso) y str en analyse_nmap_xml_scan(); se
            # normaliza a str porque write_text() sólo acepta texto.
            if isinstance(xml_output, bytes):
                xml_output = xml_output.decode("utf-8", errors="replace")
        except python_nmap.PortScannerError as error:
            detail = str(error).splitlines()[0].strip()
            if "not found" in detail.lower():
                detail = "no está en el PATH"
            raise RuntimeError(f"'nmap' no está instalado ({detail[:180]})") from error
        except Exception as error:  # noqa: BLE001 - normalizamos fallos externos
            raise RuntimeError(f"fallo ejecutando nmap vía python-nmap: {error}") from error

        out_file = self.paths["raw"] / f"nmap_{self._slug()}.xml"
        out_file.write_text(xml_output, encoding="utf-8")

        result.exit_code = 0
        try:
            result.stdout = scanner.csv() if scanner.all_hosts() else ""
        except Exception:  # noqa: BLE001 - el resumen es informativo, no crítico
            result.stdout = ""
        result.raw_path = out_file
        return result

    def gobuster(self, url: str | None = None) -> ScanResult:
        """Enumeración de directorios/archivos en un servicio HTTP."""
        cfg = self._tool_config("gobuster")
        binary = cfg.get("binary", "gobuster")
        wordlist = cfg.get("wordlist", "")
        timeout = int(cfg.get("timeout", 600))
        target_url = url or f"http://{self.target}"
        out_file = self.paths["raw"] / f"gobuster_{self._slug()}.txt"

        command = [binary, "dir", "-u", target_url, "-w", wordlist, "-q"]
        result = self._execute("gobuster", command, timeout=timeout)
        out_file.write_text(result.stdout, encoding="utf-8")
        result.raw_path = out_file
        print(f"[scanner] evidencia cruda -> {out_file}")
        return result


def main(argv: list[str] | None = None) -> int:
    """Punto de entrada CLI usado por ``scripts/run_recon.sh``."""
    parser = argparse.ArgumentParser(description="Fase 1: reconocimiento activo")
    parser.add_argument("--target", required=True, help="IP o dominio objetivo")
    parser.add_argument("--tools", default="nmap", help="Lista separada por comas: nmap,gobuster")
    parser.add_argument("--url", default=None, help="URL base para gobuster (por defecto http://<target>)")
    parser.add_argument("--config", default=None, help="Ruta alternativa a config.yaml")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    scanner = Scanner(config, args.target)

    for tool in [item.strip() for item in args.tools.split(",") if item.strip()]:
        if not scanner.is_enabled(tool):
            print(f"[scanner] {tool} deshabilitado en config.yaml, se omite")
            continue
        try:
            if tool == "nmap":
                scanner.nmap()
            elif tool == "gobuster":
                scanner.gobuster(args.url)
            else:
                print(f"[scanner] herramienta desconocida: {tool}", file=sys.stderr)
                return 1
        except RuntimeError as error:
            print(f"[scanner] ERROR: {error}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
