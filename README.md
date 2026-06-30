# Huawei Cloud Security Scanner

Herramienta de evaluacion de seguridad para cuentas de Huawei Cloud. Escanea configuraciones de IAM, VPC, ECS, OBS, CTS y ELB, genera hallazgos con niveles de severidad y produce un dashboard HTML interactivo similar a AWS Service Screener.

## Caracteristicas

- **Single Account y Multi Account**: escanea una cuenta individual o multiples cuentas usando IAM Agencies (equivalente a AWS AssumeRole)
- **Multi Region**: escanea una region, varias, o todas las regiones de Huawei Cloud en una sola ejecucion
- **6 Scanners de seguridad**: IAM, VPC/Security Groups, ECS, OBS, CTS (logging), ELB
- **Dashboard HTML interactivo**: sidebar con navegacion, graficos de severidad, tabla de hallazgos filtrable, selector de cuentas
- **Multiples formatos de reporte**: HTML, JSON, CSV
- **CLI con Rich**: interfaz de linea de comandos con progreso visual y tablas de resumen
- **Solo lectura**: no crea, modifica ni elimina ningun recurso en tu cuenta

## Estructura del Proyecto

```
huawei-cloud-security-scanner/
├── main.py                    # Entry point CLI
├── requirements.txt           # Dependencias Python
├── config/
│   └── config.yaml.example    # Plantilla de configuracion
├── core/
│   ├── auth.py                # Autenticacion (single/multi account)
│   ├── config_loader.py       # Carga y validacion de config
│   ├── models.py              # Modelos de datos (Finding, Summary)
│   └── regions.py             # Lista de regiones disponibles
├── scanners/
│   ├── base_scanner.py        # Clase base abstracta
│   ├── iam_scanner.py         # Checks de IAM
│   ├── vpc_scanner.py         # Checks de VPC/Security Groups
│   ├── ecs_scanner.py         # Checks de ECS
│   ├── obs_scanner.py         # Checks de OBS (Object Storage)
│   ├── cts_scanner.py         # Checks de CTS (Cloud Trace)
│   └── elb_scanner.py         # Checks de ELB
├── reports/
│   ├── html_report.py         # Generador de dashboard HTML
│   ├── json_report.py         # Exportador JSON
│   └── csv_report.py          # Exportador CSV
└── templates/
```

## Checks de Seguridad Implementados

| ID | Servicio | Check | Severidad |
|----|----------|-------|-----------|
| IAM-01 | IAM | Usuarios sin MFA habilitado | High |
| IAM-02 | IAM | Access keys sin rotacion (>90 dias) | Medium |
| IAM-03 | IAM | Password policy debil | High |
| IAM-04 | IAM | Grupos con permisos de admin | High |
| IAM-06 | IAM | Usuarios inactivos | Low |
| IAM-07 | IAM | Multiples access keys activas | Medium |
| VPC-01 | VPC | Puertos sensibles abiertos a 0.0.0.0/0 | Critical |
| VPC-02 | VPC | Egress sin restricciones | Medium |
| VPC-03 | VPC | Security group permite todo el trafico | Critical |
| VPC-05 | VPC | Rangos de puertos muy amplios abiertos | High |
| ECS-01 | ECS | Instancias con IP publica directa | Medium |
| ECS-03 | ECS | Instancias usando security group default | Low |
| OBS-01 | OBS | Buckets con lectura publica | Critical |
| OBS-02 | OBS | Buckets con escritura publica | Critical |
| OBS-03 | OBS | Buckets sin cifrado | Medium |
| OBS-04 | OBS | Buckets sin logging de acceso | Low |
| CTS-01 | CTS | Cloud Trace Service deshabilitado | High |
| CTS-02 | CTS | Tracker sin almacenamiento en OBS | Medium |
| CTS-03 | CTS | Tracker en estado de error | High |
| ELB-01 | ELB | Listeners sin HTTPS/TLS | High/Medium |
| ELB-03 | ELB | Version de TLS obsoleta (1.0/1.1) | High |

## Inicio Rapido

```bash
# 1. Clonar el repositorio
git clone https://github.com/daianape/huawei-cloud-security-scanner.git
cd huawei-cloud-security-scanner

# 2. Crear entorno virtual e instalar dependencias
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/Mac
pip install -r requirements.txt

# 3. Configurar credenciales
copy config\config.yaml.example config\config.yaml
# Editar config.yaml con tus credenciales

# 4. Ejecutar el scan
python main.py scan
```

## Comandos CLI

```bash
# Scan basico (region y cuenta del config)
python main.py scan

# === MODO INTERACTIVO (mas seguro, no guarda credenciales) ===
python main.py scan --interactive

# Scan de una region especifica
python main.py scan --regions la-south-2

# Scan de multiples regiones
python main.py scan --regions la-south-2,ap-southeast-1,cn-north-4

# Scan de TODAS las regiones disponibles
python main.py scan --regions all

# Solo scanners especificos
python main.py scan --scanners iam,vpc

# Elegir formatos de salida
python main.py scan --format html,json,csv

# Combinar opciones
python main.py scan --regions all --scanners iam,vpc --format html,csv --output ./reportes

# Interactivo + multi-region
python main.py scan --interactive --regions la-south-2,ap-southeast-1

# Listar regiones disponibles
python main.py list-regions

# Listar scanners disponibles
python main.py list-scanners

# Validar configuracion
python main.py validate
```

## Metodos de Autenticacion (de mas seguro a menos)

| Metodo | Comando | Credenciales en disco |
|--------|---------|----------------------|
| Prompt interactivo | `--interactive` | No, solo en memoria |
| Variables de entorno | `HWCLOUD_AK`, `HWCLOUD_SK` | No (en la sesion del shell) |
| Archivo config.yaml | `--config config.yaml` | Si (proteger con permisos) |

## Documentacion Detallada

Consulta el archivo [INSTRUCCIONES.md](INSTRUCCIONES.md) para:
- Guia paso a paso de configuracion
- Modo Single Account vs Multi Account
- Como visualizar los reportes
- Preguntas frecuentes

## Nota Importante sobre Recursos

**Esta herramienta es 100% de solo lectura.** No crea, modifica ni elimina ningun recurso en tu cuenta de Huawei Cloud. Solo realiza llamadas API de tipo GET/LIST para auditar configuraciones existentes. No hay nada que eliminar despues de ejecutarla.

## Licencia

MIT License
