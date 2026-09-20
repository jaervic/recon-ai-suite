# 02 - Metodología del reconocimiento

Basada en el estándar **PTES** (fases de *Intelligence Gathering*) y alineada con
**MITRE ATT&CK - TA0043 Reconnaissance**.

## 📋 Fases

### Fase 0 - Preparación y alcance
- Confirmar autorización escrita, ventana de ejecución y activos en alcance.
- Registrar el objetivo en `config.yaml` (`target.domain` / `target.ip`).
- Definir el *rate limit* aceptable con el cliente (flags de nmap en config).

### Fase 1 - Reconocimiento activo (`scanner.py`)
- **nmap** `-sV -sC -T4 --top-ports 1000`: puertos abiertos, versiones y scripts
  NSE por defecto. Técnica MITRE asociada: **T1046 Network Service Discovery**.
- **gobuster dir** (opcional): enumeración de rutas en servicios HTTP detectados.
- Salida guardada en `evidencia/raw/` con el comando exacto para trazabilidad.

### Fase 2 - Parseo y normalización (`parser.py`)
- XML de nmap → hosts, puertos, servicios, scripts NSE y huella de SO.
- Texto de gobuster → rutas y códigos HTTP.
- Generación de *findings* con severidad sugerida (tabla `SEVERITY_BY_PORT`) y
  recomendación base por servicio.

### Fase 3 - Priorización (`ai_prioritizer.py`)
- El LLM recibe **sólo** los hallazgos compactados (sin evidencia cruda sensible).
- Devuelve JSON estricto: severidad final, análisis de riesgo, remediación y
  técnica MITRE.
- Si no hay API disponible: heurística local equivalente, marcada como `engine=heuristic`.

### Fase 4 - Informe (`report_generator.py`)
- Resumen ejecutivo + métricas + hallazgos priorizados + inventario técnico +
  próximos pasos y anexo de alcance.
- Entrega en `evidencia/reportes/` para adjuntar al informe de pentest.

## ✅ Criterios de severidad

| Nivel | Criterio de ejemplo |
|---|---|
| Crítica | Servicio con vulnerabilidad explotable remota y sin autenticación |
| Alta | Telnet/SMB/RDP expuestos, credenciales por defecto confirmadas |
| Media | Versiones desactualizadas, rutas administrativas accesibles |
| Baja | Banner *fingerprinting*, puertos informativos |
| Informativa | Contexto útil sin impacto directo demostrado |

## 🔁 Control de calidad

1. **Validación manual obligatoria**: todo hallazgo de la IA se confirma con
   evidencia reproducible antes de reportarlo al cliente.
2. **Doble pasada**: repetir el escaneo en otro horario para descartar falsos
   positivos por filtrado intermitente.
3. **Checklist de cierre**: todos los puertos justificados, cada severidad alta
   con recomendación, informe revisado por segunda persona.

## 🧪 Ejemplo de ejecución

```bash
export DEEPSEEK_API_KEY="sk-..."
./scripts/run_recon.sh scanme.nmap.org --tools nmap
# -> evidencia/reportes/scanme.nmap.org_20260101-120000.md
```

## 📌 Buenas prácticas

- Preferir `--no-ai` cuando el alcance prohíba enviar datos a terceros.
- Conservar `evidencia/raw/` sólo durante el proyecto; luego archivar cifrado.
- Documentar toda desviación de alcance o incidencia durante el escaneo.
