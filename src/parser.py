"""Parsea la salida cruda de las herramientas a JSON estructurado.

Lee ``evidencia/raw/*`` y genera ``evidencia/parsed/<target>.json`` con hosts,
puertos, rutas web y una lista plana de hallazgos lista para la IA.

Uso:
    python -m src.parser --target scanme.nmap.org
"""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from . import ensure_dir, load_config, paths_from_config

# Heurística base de severidad por puerto (navaja suiza previa al LLM).
SEVERITY_BY_PORT: dict[int, str] = {
    21: "media",    # FTP plano
    23: "alta",     # Telnet plano
    25: "media",    # SMTP abierto
    111: "media",   # rpcbind
    445: "alta",    # SMB
    1433: "media",  # MSSQL
    3306: "media",  # MySQL
    3389: "alta",   # RDP
    5900: "alta",   # VNC
}

SERVICE_RECOMMENDATIONS: dict[str, str] = {
    "ftp": "Verificar si acepta login anónimo y si el canal es cifrado (migrar a SFTP/FTPS).",
    "telnet": "Servicio en texto plano: deshabilitar y reemplazar por SSH.",
    "ssh": "Confirmar versión parcheada, deshabilitar login de root y forzar claves.",
    "http": "Revisar cabeceras de seguridad, TLS y rutas expuestas (ver gobuster).",
    "https": "Validar certificado, caducidad, protocolos obsoletos (TLS 1.0/1.1) y HSTS.",
    "smb": "Comprobar firmado SMB, versiones (SMBv1) y permisos de recursos compartidos.",
    "rdp": "Restringir por VPN/lista blanca, exigir NLA y MFA.",
    "mysql": "No exponer bases de datos a Internet; limitar por firewall y usuario.",
}


def parse_nmap_xml(xml_path: str | Path) -> list[dict]:
    """Convierte un XML de nmap (``-oX``) en una lista de hosts normalizados."""
    path = Path(xml_path)
    if not path.exists():
        return []

    root = ET.parse(path).getroot()
    hosts: list[dict] = []
    for host_node in root.findall("host"):
        status = host_node.find("status")
        if status is not None and status.get("state") == "down":
            continue

        addresses = [
            addr.get("addr", "") for addr in host_node.findall("address") if addr.get("addr")
        ]
        hostname = ""
        hostnames = host_node.find("hostnames")
        if hostnames is not None:
            entry = hostnames.find("hostname")
            if entry is not None:
                hostname = entry.get("name", "")

        os_match = ""
        os_node = host_node.find("os")
        if os_node is not None:
            match = os_node.find("osmatch")
            if match is not None:
                os_match = match.get("name", "")

        ports: list[dict] = []
        ports_node = host_node.find("ports")
        if ports_node is not None:
            for port_node in ports_node.findall("port"):
                state_node = port_node.find("state")
                if state_node is not None and state_node.get("state") != "open":
                    continue
                service_node = port_node.find("service")
                scripts = [
                    {"id": script.get("id", ""), "output": (script.get("output") or "").strip()}
                    for script in port_node.findall("script")
                ]
                ports.append(
                    {
                        "port": int(port_node.get("portid", 0)),
                        "protocol": port_node.get("protocol", "tcp"),
                        "state": state_node.get("state") if state_node is not None else "unknown",
                        "service": service_node.get("name", "") if service_node is not None else "",
                        "product": service_node.get("product", "") if service_node is not None else "",
                        "version": service_node.get("version", "") if service_node is not None else "",
                        "extrainfo": (
                            service_node.get("extrainfo", "") if service_node is not None else ""
                        ),
                        "scripts": scripts,
                    }
                )

        hosts.append(
            {
                "ip": addresses[0] if addresses else "",
                "addresses": addresses,
                "hostname": hostname,
                "os": os_match,
                "ports": sorted(ports, key=lambda item: item["port"]),
            }
        )
    return hosts


# Formatos soportados: "/(Status: 200) [Size: 1234]" y "/admin   (Status: 301)"
STATUS_RE = re.compile(r"Status:\s*(\d{3})")
SIZE_RE = re.compile(r"Size:\s*(\d+)")


def parse_gobuster_txt(txt_path: str | Path) -> list[dict]:
    """Parsea la salida de ``gobuster dir`` y devuelve las rutas encontradas."""
    path = Path(txt_path)
    if not path.exists():
        return []

    entries: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        route = line.split()[0].lstrip("/")
        status_match = STATUS_RE.search(line)
        size_match = SIZE_RE.search(line)
        entries.append(
            {
                "path": f"/{route}",
                "status": status_match.group(1) if status_match else "",
                "size": int(size_match.group(1)) if size_match else None,
                "raw": line,
            }
        )
    return entries


def build_findings(hosts: list[dict], web_paths: list[dict]) -> list[dict]:
    """Aplana hosts/puertos/rutas en hallazgos accionables con severidad sugerida."""
    findings: list[dict] = []
    for host in hosts:
        for port in host["ports"]:
            service = port["service"].lower()
            severity = SEVERITY_BY_PORT.get(port["port"])
            if severity is None:
                severity = "baja" if service in {"http", "https", "ssh"} else "media"
            evidence = " ".join(
                part for part in [port["product"], port["version"], port["extrainfo"]] if part
            )
            findings.append(
                {
                    "id": f"PORT-{port['port']}/{port['protocol']}",
                    "source": "nmap",
                    "host": host["ip"],
                    "title": (
                        f"Servicio expuesto: {service or 'desconocido'} en "
                        f"{port['port']}/{port['protocol']}"
                    ),
                    "severity_hint": severity,
                    "evidence": evidence or port["state"],
                    "recommendation": SERVICE_RECOMMENDATIONS.get(
                        service, "Revisar necesidad del servicio, versión y controles de acceso."
                    ),
                }
            )
        if not host["ports"]:
            findings.append(
                {
                    "id": "HOST-NO-OPEN-PORTS",
                    "source": "nmap",
                    "host": host["ip"],
                    "title": "Host activo sin puertos abiertos detectados",
                    "severity_hint": "informativa",
                    "evidence": host.get("os") or "Sin huella de SO",
                    "recommendation": "Repetir el escaneo con --top-ports ampliado o rango -p-.",
                }
            )

    for entry in web_paths:
        status = entry.get("status", "")
        severity = "media" if status in {"200", "204", "301", "302", "401", "403"} else "informativa"
        findings.append(
            {
                "id": f"WEB-{entry['path']}",
                "source": "gobuster",
                "host": "",
                "title": f"Ruta web descubierta: {entry['path']} (HTTP {status or 'n/d'})",
                "severity_hint": severity,
                "evidence": entry.get("raw", ""),
                "recommendation": "Validar autenticación, exposición de información y ficheros sensibles.",
            }
        )
    return findings


def parse_target(target: str, config: dict | None = None) -> dict:
    """Ejecuta el parseo completo y devuelve el documento JSON estructurado."""
    config = config if config is not None else load_config()
    paths = paths_from_config(config)
    slug = target.replace("/", "_").replace(":", "_")

    hosts = parse_nmap_xml(paths["raw"] / f"nmap_{slug}.xml")
    web_paths = parse_gobuster_txt(paths["raw"] / f"gobuster_{slug}.txt")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": target,
        "summary": {
            "hosts_up": len(hosts),
            "open_ports": sum(len(host["ports"]) for host in hosts),
            "web_paths": len(web_paths),
        },
        "hosts": hosts,
        "web_paths": web_paths,
        "findings": build_findings(hosts, web_paths),
    }


def main(argv: list[str] | None = None) -> int:
    """Punto de entrada CLI: escribe el JSON estructurado en evidencia/parsed/."""
    parser = argparse.ArgumentParser(description="Fase 2: parseo de salidas a JSON")
    parser.add_argument("--target", required=True, help="IP o dominio objetivo")
    parser.add_argument("--config", default=None, help="Ruta alternativa a config.yaml")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    document = parse_target(args.target, config)

    paths = paths_from_config(config)
    ensure_dir(paths["parsed"])
    out_file = paths["parsed"] / f"{args.target.replace('/', '_')}.json"
    out_file.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")

    summary = document["summary"]
    print(
        f"[parser] {out_file} -> {summary['hosts_up']} host(s), "
        f"{summary['open_ports']} puerto(s), {summary['web_paths']} ruta(s) web, "
        f"{len(document['findings'])} hallazgo(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
