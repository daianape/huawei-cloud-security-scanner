# Huawei Cloud Security Scanner

Herramienta de evaluacion de seguridad para cuentas de Huawei Cloud. Escanea configuraciones de IAM, VPC, ECS, OBS, CTS y ELB, genera hallazgos con niveles de severidad y produce un dashboard HTML interactivo similar a AWS Service Screener.

## Caracteristicas

- **Single Account y Multi Account**: escanea una cuenta individual o multiples cuentas usando IAM Agencies
- **Multi Region**: escanea una region, varias, o todas las regiones configuradas en una sola ejecucion
- **6 Scanners de seguridad**: IAM, VPC/Security Groups, ECS, OBS, CTS (logging), ELB
- **Dashboard HTML interactivo**: sidebar con navegacion, graficos de severidad, tabla de hallazgos filtrable
- **Multiples formatos de reporte**: HTML, JSON, CSV
- **Credenciales seguras**: AK/SK se pasan por variables de entorno, nunca en archivos
- **Solo lectura**: no crea, modifica ni elimina ningun recurso en tu cuenta

## Inicio Rapido

```bash
# 1. Clonar e instalar
git clone https://github.com/daianape/huawei-cloud-security-scanner.git
cd huawei-cloud-security-scanner
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# 2. Configurar regiones
copy config\config.yaml.example config\config.yaml
# Editar config.yaml: completar domain_id y project_ids de tus regiones

# 3. Configurar credenciales (variables de entorno)
set HWCLOUD_AK=tu_access_key
set HWCLOUD_SK=tu_secret_key

# 4. Ejecutar
python main.py scan --no-verify-ssl
```

## Autenticacion

Las credenciales se pasan **exclusivamente por variables de entorno** por seguridad:

| Variable | Descripcion | Obligatoria |
|----------|-------------|-------------|
| `HWCLOUD_AK` | Access Key | Si |
| `HWCLOUD_SK` | Secret Key | Si |

El `domain_id` y los `project_id` van en `config/config.yaml` (son identificadores publicos, no secretos).

## Comandos CLI

```bash
# Scan region principal
python main.py scan --no-verify-ssl

# Scan region especifica
python main.py scan --no-verify-ssl --regions la-south-2

# Scan multiples regiones
python main.py scan --no-verify-ssl --regions la-south-2,la-north-2

# Scan TODAS las regiones configuradas
python main.py scan --no-verify-ssl --regions all

# Solo scanners especificos
python main.py scan --no-verify-ssl --scanners iam,vpc

# Formatos de salida
python main.py scan --no-verify-ssl --format html,json,csv

# Listar regiones / scanners
python main.py list-regions
python main.py list-scanners

# Validar configuracion
python main.py validate
```

## Estructura del Proyecto

```
huawei-cloud-security-scanner/
├── main.py                    # Entry point CLI
├── requirements.txt           # Dependencias Python
├── config/
│   └── config.yaml.example    # Plantilla (regiones, sin credenciales)
├── core/
│   ├── auth.py                # Autenticacion (single/multi account)
│   ├── config_loader.py       # Carga config + env vars
│   ├── models.py              # Modelos de datos
│   └── regions.py             # Lista de regiones disponibles
├── scanners/
│   ├── base_scanner.py        # Clase base
│   ├── iam_scanner.py         # IAM checks
│   ├── vpc_scanner.py         # VPC/Security Groups checks
│   ├── ecs_scanner.py         # ECS checks
│   ├── obs_scanner.py         # OBS checks
│   ├── cts_scanner.py         # CTS checks
│   └── elb_scanner.py         # ELB checks
├── reports/
│   ├── html_report.py         # Dashboard HTML
│   ├── json_report.py         # JSON export
│   └── csv_report.py          # CSV export
└── output/                    # Reportes generados (gitignored)
```

## Checks de Seguridad

| ID | Servicio | Check | Severidad |
|----|----------|-------|-----------|
| IAM-01 | IAM | Usuarios sin MFA | High |
| IAM-02 | IAM | Access keys sin rotacion (>90 dias) | Medium |
| IAM-03 | IAM | Password policy debil | High |
| IAM-04 | IAM | Grupos con permisos admin | High |
| IAM-06 | IAM | Usuarios inactivos | Low |
| IAM-07 | IAM | Multiples access keys activas | Medium |
| VPC-01 | VPC | Puertos sensibles abiertos a 0.0.0.0/0 | Critical |
| VPC-02 | VPC | Egress sin restricciones | Medium |
| VPC-03 | VPC | Security group permite todo el trafico | Critical |
| VPC-05 | VPC | Rangos de puertos amplios abiertos | High |
| ECS-01 | ECS | Instancias con IP publica directa | Medium |
| ECS-03 | ECS | Instancias usando SG default | Low |
| OBS-01 | OBS | Buckets con lectura publica | Critical |
| OBS-02 | OBS | Buckets con escritura publica | Critical |
| OBS-03 | OBS | Buckets sin cifrado | Medium |
| OBS-04 | OBS | Buckets sin logging | Low |
| CTS-01 | CTS | Cloud Trace Service deshabilitado | High |
| CTS-02 | CTS | Tracker sin almacenamiento en OBS | Medium |
| ELB-01 | ELB | Listeners sin HTTPS/TLS | High |
| ELB-03 | ELB | Version TLS obsoleta | High |

## Documentacion Detallada

Ver [INSTRUCCIONES.md](INSTRUCCIONES.md) para:
- Guia paso a paso completa
- Como crear el usuario IAM con permisos
- Como agregar nuevas regiones
- Modo Multi Account
- Troubleshooting

## Nota sobre Recursos

**Esta herramienta es 100% de solo lectura.** No crea, modifica ni elimina recursos. Solo realiza llamadas API de tipo GET/LIST. No hay nada que eliminar despues de ejecutarla.

## Licencia

MIT License
