"""Tests de ``src/parser.py``: normalización de evidencia cruda a JSON.

Cubren el parseo de XML de nmap, la salida de gobuster, las tablas de
severidad y la integración ``parse_target`` / CLI ``main`` sin tocar la red.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from src import parser

# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def _finding(findings: list[dict], finding_id: str) -> dict:
    matches = [item for item in findings if item["id"] == finding_id]
    assert matches, f"No se encontró el hallazgo {finding_id!r}: {[f['id'] for f in findings]}"
    return matches[0]


# ---------------------------------------------------------------------------
# parse_nmap_xml
# ---------------------------------------------------------------------------


def test_parse_nmap_archivo_inexistente_devuelve_lista_vacia(tmp_path: Path) -> None:
    assert parser.parse_nmap_xml(tmp_path / "no_existe.xml") == []


def test_parse_nmap_excluye_hosts_down(sample_hosts: list[dict]) -> None:
    ips = [host["ip"] for host in sample_hosts]
    assert ips == ["192.168.56.10", "192.168.56.11"]
    assert "192.168.56.99" not in ips


def test_parse_nmap_normaliza_hostname_os_y_direcciones(sample_hosts: list[dict]) -> None:
    host = sample_hosts[0]
    assert host["ip"] == "192.168.56.10"
    assert host["addresses"] == ["192.168.56.10", "fe80::a00:27ff:fe4e:66a1"]
    assert host["hostname"] == "victima.local"
    assert host["os"] == "Linux 5.4 - 5.15"


def test_parse_nmap_ordena_puertos_y_omite_no_abiertos(sample_hosts: list[dict]) -> None:
    ports = sample_hosts[0]["ports"]
    assert [port["port"] for port in ports] == [22, 80, 3306]
    assert all(port["state"] == "open" for port in ports)
    assert 9999 not in [port["port"] for port in ports]


def test_parse_nmap_extrae_metadatos_de_servicio(sample_hosts: list[dict]) -> None:
    ports = {port["port"]: port for port in sample_hosts[0]["ports"]}
    assert ports[22]["service"] == "ssh"
    assert ports[22]["product"] == "OpenSSH"
    assert ports[22]["version"] == "8.9p1 Ubuntu"
    assert ports[22]["extrainfo"] == "Ubuntu Linux; protocol 2.0"
    assert ports[80]["service"] == "http"
    assert ports[80]["product"] == "Apache httpd"
    assert ports[80]["version"] == "2.4.41"
    assert ports[3306]["service"] == "mysql"
    assert ports[3306]["product"] == "MySQL"
    assert ports[3306]["version"] == "8.0.32"


def test_parse_nmap_extrae_scripts_con_output_stripped(sample_hosts: list[dict]) -> None:
    ports = {port["port"]: port for port in sample_hosts[0]["ports"]}
    assert ports[22]["scripts"] == [
        {"id": "ssh-hostkey", "output": "2048 SHA256:abc123 (RSA)\n  256 SHA256:def456 (ED25519)"}
    ]
    assert [script["id"] for script in ports[80]["scripts"]] == [
        "http-title",
        "http-server-header",
    ]
    assert ports[80]["scripts"][1]["output"] == "Apache/2.4.41 (Ubuntu)"
    assert ports[3306]["scripts"][0]["output"].startswith("Protocol: 10")


def test_parse_nmap_host_sin_puertos_abiertos(sample_hosts: list[dict]) -> None:
    host = sample_hosts[1]
    assert host["hostname"] == "db.local"
    assert host["os"] == ""
    assert host["ports"] == []


def test_parse_nmap_xml_valido_sin_hosts_devuelve_vacio(tmp_path: Path) -> None:
    xml = _write(tmp_path, "vacio.xml", "<nmaprun></nmaprun>")
    assert parser.parse_nmap_xml(xml) == []


def test_parse_nmap_puerto_sin_nodo_state_se_marca_unknown(tmp_path: Path) -> None:
    xml = _write(
        tmp_path,
        "sin_state.xml",
        (
            "<nmaprun><host><status state='up'/>"
            "<address addr='10.0.0.5' addrtype='ipv4'/>"
            "<ports><port protocol='tcp' portid='1234'>"
            "<service name='custom'/></port></ports>"
            "</host></nmaprun>"
        ),
    )
    hosts = parser.parse_nmap_xml(xml)
    assert len(hosts) == 1
    assert hosts[0]["ports"][0]["port"] == 1234
    assert hosts[0]["ports"][0]["state"] == "unknown"


def test_parse_nmap_xml_vacio_devuelve_lista_vacia(tmp_path: Path) -> None:
    # Comportamiento robusto deseado: un XML de 0 bytes no debe romper el pipeline.
    xml = _write(tmp_path, "cero_bytes.xml", "")
    assert parser.parse_nmap_xml(xml) == []


def test_parse_nmap_xml_malformado_devuelve_lista_vacia(tmp_path: Path) -> None:
    # Comportamiento robusto deseado: XML truncado/corrupto no debe lanzar excepción.
    xml = _write(tmp_path, "malformado.xml", "<nmaprun><host><status state='up'>")
    assert parser.parse_nmap_xml(xml) == []


# ---------------------------------------------------------------------------
# parse_gobuster_txt
# ---------------------------------------------------------------------------


def test_parse_gobuster_archivo_inexistente_devuelve_lista_vacia(tmp_path: Path) -> None:
    assert parser.parse_gobuster_txt(tmp_path / "no_existe.txt") == []


def test_parse_gobuster_parsea_status_y_size(sample_web_paths: list[dict]) -> None:
    assert len(sample_web_paths) == 7
    by_path = {entry["path"]: entry for entry in sample_web_paths}
    assert by_path["/admin"]["status"] == "301"
    assert by_path["/admin"]["size"] == 316
    assert by_path["/index.html"]["status"] == "200"
    assert by_path["/index.html"]["size"] == 10918
    assert by_path["/backup.zip"]["status"] == "200"
    assert by_path["/backup.zip"]["size"] == 10485760
    assert by_path["/secret"]["status"] == "401"
    assert by_path["/secret"]["size"] == 0


def test_parse_gobuster_normaliza_path_y_conserva_raw(sample_web_paths: list[dict]) -> None:
    entry = sample_web_paths[0]
    assert entry["path"] == "/admin"
    assert entry["raw"] == (
        "/admin                (Status: 301) [Size: 316] "
        "[--> http://192.168.56.10/admin/]"
    )


def test_parse_gobuster_ignora_lineas_vacias(tmp_path: Path) -> None:
    txt = _write(tmp_path, "con_blancos.txt", "\n/admin (Status: 200) [Size: 1]\n\n   \n")
    entries = parser.parse_gobuster_txt(txt)
    assert [entry["path"] for entry in entries] == ["/admin"]


def test_parse_gobuster_ignora_linea_sin_status(tmp_path: Path) -> None:
    # Contrato (opción A): una línea sin "(Status: NNN)" no es un resultado de gobuster.
    txt = _write(tmp_path, "sin_status.txt", "/api\n")
    assert parser.parse_gobuster_txt(txt) == []


def test_parse_gobuster_ignora_lineas_basura(tmp_path: Path) -> None:
    # Comportamiento robusto deseado: el banner y el progreso no son rutas web.
    txt = _write(
        tmp_path,
        "con_basura.txt",
        (
            "===============================================================\n"
            "Gobuster v3.6\n"
            "[+] Url:                     http://192.168.56.10/\n"
            "[+] Wordlist:                /usr/share/wordlists/common.txt\n"
            "Starting gobuster in directory enumeration mode\n"
            "===============================================================\n"
            "/admin                (Status: 301) [Size: 316]\n"
            "Progress: 4614 / 4615 (99.98%)\n"
            "===============================================================\n"
            "Finished\n"
        ),
    )
    entries = parser.parse_gobuster_txt(txt)
    assert [entry["path"] for entry in entries] == ["/admin"]


# ---------------------------------------------------------------------------
# build_findings / heurística de severidad
# ---------------------------------------------------------------------------


def test_severity_by_port_cubre_puertos_criticos() -> None:
    assert parser.SEVERITY_BY_PORT[23] == "alta"
    assert parser.SEVERITY_BY_PORT[445] == "alta"
    assert parser.SEVERITY_BY_PORT[3389] == "alta"
    assert parser.SEVERITY_BY_PORT[5900] == "alta"
    assert parser.SEVERITY_BY_PORT[21] == "media"
    assert parser.SEVERITY_BY_PORT[3306] == "media"


def test_service_recommendations_cubre_servicios_clave() -> None:
    for service in ("ftp", "telnet", "ssh", "http", "https", "smb", "rdp", "mysql"):
        assert service in parser.SERVICE_RECOMMENDATIONS
        assert parser.SERVICE_RECOMMENDATIONS[service]


def test_build_findings_severidad_por_puerto(sample_hosts: list[dict]) -> None:
    findings = parser.build_findings(sample_hosts, [])
    assert _finding(findings, "PORT-22/tcp")["severity_hint"] == "baja"
    assert _finding(findings, "PORT-80/tcp")["severity_hint"] == "baja"
    assert _finding(findings, "PORT-3306/tcp")["severity_hint"] == "media"


def test_build_findings_recomendacion_por_servicio(sample_hosts: list[dict]) -> None:
    findings = parser.build_findings(sample_hosts, [])
    assert (
        _finding(findings, "PORT-80/tcp")["recommendation"]
        == parser.SERVICE_RECOMMENDATIONS["http"]
    )
    assert _finding(findings, "PORT-22/tcp")["recommendation"] == parser.SERVICE_RECOMMENDATIONS["ssh"]


def test_build_findings_host_sin_puertos(sample_hosts: list[dict]) -> None:
    findings = parser.build_findings(sample_hosts, [])
    finding = _finding(findings, "HOST-NO-OPEN-PORTS")
    assert finding["host"] == "192.168.56.11"
    assert finding["severity_hint"] == "informativa"
    assert finding["evidence"] == "Sin huella de SO"


def test_build_findings_web_severidad_por_status() -> None:
    web_paths = [
        {"path": "/ok", "status": "200", "size": 10, "raw": "/ok"},
        {"path": "/redir", "status": "301", "size": 0, "raw": "/redir"},
        {"path": "/err", "status": "500", "size": 0, "raw": "/err"},
    ]
    findings = parser.build_findings([], web_paths)
    assert _finding(findings, "WEB-/ok")["severity_hint"] == "media"
    assert _finding(findings, "WEB-/redir")["severity_hint"] == "media"
    assert _finding(findings, "WEB-/err")["severity_hint"] == "informativa"


def test_build_findings_evidence_join_y_fallback() -> None:
    hosts = [
        {
            "ip": "10.0.0.1",
            "os": "",
            "ports": [
                {
                    "port": 21,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ftp",
                    "product": "",
                    "version": "",
                    "extrainfo": "",
                    "scripts": [],
                }
            ],
        }
    ]
    finding = _finding(parser.build_findings(hosts, []), "PORT-21/tcp")
    assert finding["severity_hint"] == "media"
    assert finding["evidence"] == "open"


def test_build_findings_sin_datos_no_genera_hallazgos() -> None:
    assert parser.build_findings([], []) == []


# ---------------------------------------------------------------------------
# parse_target (integración sin red)
# ---------------------------------------------------------------------------


def test_parse_target_estructura_y_resumen(config_with_fixtures: dict) -> None:
    document = parser.parse_target("192.168.56.10", config_with_fixtures)
    assert set(document) == {
        "generated_at",
        "target",
        "summary",
        "hosts",
        "web_paths",
        "findings",
    }
    assert document["target"] == "192.168.56.10"
    assert document["summary"] == {"hosts_up": 2, "open_ports": 3, "web_paths": 7}
    assert len(document["findings"]) == 11
    datetime.fromisoformat(document["generated_at"])


def test_parse_target_sin_evidencia_no_falla(tmp_config: dict) -> None:
    document = parser.parse_target("192.168.56.10", tmp_config)
    assert document["hosts"] == []
    assert document["web_paths"] == []
    assert document["findings"] == []
    assert document["summary"] == {"hosts_up": 0, "open_ports": 0, "web_paths": 0}


def test_parse_target_slug_reemplaza_slash_y_dos_puntos(
    tmp_path: Path, config_with_fixtures: dict, nmap_xml_path: Path
) -> None:
    base = Path(config_with_fixtures["project"]["output_dir"])
    raw = base / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "nmap_http___x.xml").write_bytes(nmap_xml_path.read_bytes())

    document = parser.parse_target("http://x", config_with_fixtures)
    assert document["target"] == "http://x"
    assert document["summary"]["hosts_up"] == 2


# ---------------------------------------------------------------------------
# CLI main
# ---------------------------------------------------------------------------


def test_main_escribe_json_y_devuelve_cero(
    config_file: Path, config_with_fixtures: dict, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = parser.main(["--target", "192.168.56.10", "--config", str(config_file)])
    assert exit_code == 0

    out_file = Path(config_with_fixtures["project"]["output_dir"]) / "parsed" / "192.168.56.10.json"
    assert out_file.exists()

    written = json.loads(out_file.read_text(encoding="utf-8"))
    assert written["summary"] == {"hosts_up": 2, "open_ports": 3, "web_paths": 7}

    captured = capsys.readouterr().out
    assert "[parser]" in captured
    assert "2 host(s)" in captured
