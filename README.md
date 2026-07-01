# Huawei Cloud Security Scanner

Herramienta de evaluacion de seguridad para cuentas de Huawei Cloud. Escanea configuraciones de 28 servicios, genera hallazgos con niveles de severidad y produce un dashboard HTML interactivo similar a AWS Service Screener.

## Caracteristicas

- **Single Account y Multi Account**: escanea una cuenta individual o multiples cuentas usando IAM Agencies
- **Multi Region**: escanea una region, varias, o todas las regiones configuradas en una sola ejecucion
- **Regiones custom/locales**: soporte para regiones no registradas en el SDK (ej: `sa-argentina-1` Buenos Aires) mediante fallback a endpoint manual
- **28 Scanners de seguridad**: cobertura integral de IAM, Red, Compute, Storage, Logging y Gobernanza
- **Dashboard HTML interactivo**: sidebar con navegacion, graficos de severidad, tabla de hallazgos filtrable, vista detalle por servicio con cards de recursos individuales
- **Multiples formatos de reporte**: HTML, JSON, CSV
- **Credenciales seguras**: AK/SK se pasan por variables de entorno, nunca en archivos
- **Solo lectura**: no crea, modifica ni elimina ningun recurso en tu cuenta
- **Rate limiting inteligente**: delays entre checks y regiones, retry automatico ante throttling
- **Auto-discovery de Project IDs**: detecta automaticamente los project_id de todas las regiones

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

### Sobre `--no-verify-ssl`

Este flag deshabilita la verificacion de certificados SSL al conectar con las APIs de Huawei Cloud.

**Cuando usarlo:**
- Si tu red corporativa tiene un proxy/firewall que intercepta trafico HTTPS (genera errores de "self-signed certificate" o "CERTIFICATE_VERIFY_FAILED")
- Si estas detras de un proxy empresarial que reemplaza certificados SSL

**Cuando NO es necesario:**
- Si ejecutas el scanner desde una red domestica sin proxy corporativo
- Si no ves errores de certificado SSL al ejecutar sin el flag

Si no lo necesitas, simplemente omitilo: `python main.py scan --regions all`

### Ejemplos

```bash
# Scan region principal
python main.py scan --no-verify-ssl

# Scan region especifica
python main.py scan --no-verify-ssl --regions la-south-2

# Scan multiples regiones
python main.py scan --no-verify-ssl --regions la-south-2,la-north-2

# Scan TODAS las regiones configuradas (ignora las que tienen project_id vacio)
python main.py scan --no-verify-ssl --regions all

# Solo scanners especificos
python main.py scan --no-verify-ssl --scanners iam,vpc,rds,kms

# Formatos de salida
python main.py scan --no-verify-ssl --format html,json,csv

# Sin proxy corporativo (no necesita --no-verify-ssl)
python main.py scan --regions all

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
│   ├── auth.py                # Autenticacion (single/multi account, auto-discovery)
│   ├── config_loader.py       # Carga config + env vars
│   ├── models.py              # Modelos de datos (Finding, ScanResult, Severity)
│   └── regions.py             # Lista de regiones disponibles (21 regiones)
├── scanners/
│   ├── base_scanner.py        # Clase base (con soporte regiones custom)
│   ├── iam_scanner.py         # IAM checks
│   ├── vpc_scanner.py         # VPC/Security Groups checks
│   ├── ecs_scanner.py         # ECS checks
│   ├── obs_scanner.py         # OBS checks
│   ├── cts_scanner.py         # CTS checks
│   ├── elb_scanner.py         # ELB checks
│   ├── identity_center_scanner.py  # IAM Identity Center checks
│   ├── rds_scanner.py         # RDS (bases de datos) checks
│   ├── dcs_scanner.py         # DCS/Redis checks
│   ├── nat_scanner.py         # NAT Gateway checks
│   ├── eip_scanner.py         # Elastic IP checks
│   ├── waf_scanner.py         # Web Application Firewall checks
│   ├── cfw_scanner.py         # Cloud Firewall checks
│   ├── evs_scanner.py         # Elastic Volume Service checks
│   ├── kms_scanner.py         # Key Management checks
│   ├── cce_scanner.py         # Cloud Container Engine checks
│   ├── cbr_scanner.py         # Cloud Backup and Recovery checks
│   ├── vpn_scanner.py         # VPN checks
│   ├── dns_scanner.py         # DNS checks
│   ├── sfs_scanner.py         # Scalable File Service checks
│   ├── functiongraph_scanner.py  # Serverless (FunctionGraph) checks
│   ├── ces_scanner.py         # Cloud Eye (monitoring) checks
│   ├── lts_scanner.py         # Log Tank Service checks
│   ├── config_scanner.py      # Config/RMS (compliance) checks
│   ├── smn_scanner.py         # Simple Message Notification checks
│   ├── bms_scanner.py         # Bare Metal Server checks
│   ├── ims_scanner.py         # Image Management checks
│   └── tms_scanner.py         # Tag Management checks
├── reports/
│   ├── html_report.py         # Dashboard HTML
│   ├── json_report.py         # JSON export
│   └── csv_report.py          # CSV export
└── output/                    # Reportes generados (gitignored)
```

## Scanners Disponibles (28)

### Identidad y Acceso (IAM)

| Scanner | Servicio | Descripcion |
|---------|----------|-------------|
| `iam` | IAM | Usuarios, MFA, access keys, password policy, permisos |
| `identity-center` | Identity Center | Permission sets, duracion de sesiones |
| `kms` | KMS/DEW | Rotacion de CMKs, keys pendientes de eliminacion |
| `tms` | TMS | Tags predefinidos, gobernanza de etiquetado |

### Red (Network)

| Scanner | Servicio | Descripcion |
|---------|----------|-------------|
| `vpc` | VPC | Security groups, puertos abiertos, reglas de egress |
| `nat` | NAT Gateway | Reglas DNAT exponiendo puertos sensibles |
| `eip` | Elastic IP | IPs no asociadas a recursos |
| `waf` | WAF | Dominios sin proteccion, modo deteccion |
| `cfw` | Cloud Firewall | Firewall no activo |
| `vpn` | VPN | Cifrado debil (DES/3DES) |
| `dns` | DNS | Zonas publicas, registros expuestos |
| `elb` | ELB | Listeners sin HTTPS, TLS obsoleto |

### Computo (Compute)

| Scanner | Servicio | Descripcion |
|---------|----------|-------------|
| `ecs` | ECS | IPs publicas directas, SG default |
| `cce` | CCE | API publica, K8s desactualizado |
| `bms` | BMS | Bare Metal con IP publica, SG default |
| `functiongraph` | FunctionGraph | Funciones sin VPC |
| `ims` | IMS | Imagenes publicas, imagenes antiguas |

### Almacenamiento (Storage)

| Scanner | Servicio | Descripcion |
|---------|----------|-------------|
| `obs` | OBS | Buckets publicos, sin cifrado, sin logging |
| `rds` | RDS | Acceso publico, backups, SSL |
| `dcs` | DCS/Redis | Sin password, acceso publico, sin SSL |
| `evs` | EVS | Volumenes sin cifrado |
| `sfs` | SFS Turbo | File systems sin cifrado |
| `cbr` | CBR | Vaults vacios, retencion de backup |

### Logging y Monitoreo

| Scanner | Servicio | Descripcion |
|---------|----------|-------------|
| `cts` | CTS | Cloud Trace deshabilitado, sin almacenamiento OBS |
| `ces` | Cloud Eye | Alarmas no configuradas |
| `lts` | LTS | Retencion de logs corta |
| `config` | Config/RMS | Reglas de compliance no configuradas |
| `smn` | SMN | Topicos de notificacion |

## Checks de Seguridad (Catalogo Completo)

### IAM

| ID | Check | Severidad |
|----|-------|-----------|
| IAM-01 | Usuarios sin MFA | High |
| IAM-02 | Access keys sin rotacion (>90 dias) | Medium |
| IAM-03 | Password policy debil | High |
| IAM-04 | Grupos con permisos admin | High |
| IAM-06 | Usuarios inactivos | Low |
| IAM-07 | Multiples access keys activas | Medium |

### Identity Center

| ID | Check | Severidad |
|----|-------|-----------|
| IDC-01 | Permission sets con acceso admin | High |
| IDC-03 | Sesion excesivamente larga (>4h) | Medium |

### VPC

| ID | Check | Severidad |
|----|-------|-----------|
| VPC-01 | Puertos sensibles abiertos a 0.0.0.0/0 | Critical |
| VPC-02 | Egress sin restricciones | Medium |
| VPC-03 | Security group permite todo el trafico | Critical |
| VPC-05 | Rangos de puertos amplios abiertos | High |

### ECS

| ID | Check | Severidad |
|----|-------|-----------|
| ECS-01 | Instancias con IP publica directa | Medium |
| ECS-03 | Instancias usando SG default | Low |

### OBS

| ID | Check | Severidad |
|----|-------|-----------|
| OBS-01 | Buckets con lectura publica | Critical |
| OBS-02 | Buckets con escritura publica | Critical |
| OBS-03 | Buckets sin cifrado | Medium |
| OBS-04 | Buckets sin logging | Low |

### CTS

| ID | Check | Severidad |
|----|-------|-----------|
| CTS-01 | Cloud Trace Service deshabilitado | High |
| CTS-02 | Tracker sin almacenamiento en OBS | Medium |

### ELB

| ID | Check | Severidad |
|----|-------|-----------|
| ELB-01 | Listeners sin HTTPS/TLS | High |
| ELB-03 | Version TLS obsoleta | High |

### RDS

| ID | Check | Severidad |
|----|-------|-----------|
| RDS-01 | Base de datos con acceso publico (EIP) | Critical |
| RDS-03 | Sin backup automatico o retencion insuficiente | High |
| RDS-04 | SSL no habilitado | High |

### DCS (Redis)

| ID | Check | Severidad |
|----|-------|-----------|
| DCS-01 | Instancia sin password | Critical |
| DCS-02 | Instancia con acceso publico | Critical |
| DCS-03 | Sin SSL/TLS | Medium |

### NAT Gateway

| ID | Check | Severidad |
|----|-------|-----------|
| NAT-01 | Regla DNAT detectada (revision manual) | Low |
| NAT-02 | DNAT expone puerto sensible (SSH, RDP, DB) | Critical |

### EIP

| ID | Check | Severidad |
|----|-------|-----------|
| EIP-01 | EIP sin asociar a recurso | Low |

### WAF

| ID | Check | Severidad |
|----|-------|-----------|
| WAF-01 | Dominio sin proteccion WAF | High |
| WAF-02 | WAF en modo solo deteccion (no bloquea) | Medium |

### Cloud Firewall (CFW)

| ID | Check | Severidad |
|----|-------|-----------|
| CFW-01 | Cloud Firewall no desplegado o inactivo | High |

### EVS

| ID | Check | Severidad |
|----|-------|-----------|
| EVS-01 | Volumen sin cifrado | Medium |

### KMS

| ID | Check | Severidad |
|----|-------|-----------|
| KMS-01 | CMK pendiente de eliminacion | High |
| KMS-02 | CMK sin rotacion automatica | Medium |
| KMS-03 | CMK deshabilitada | Medium |

### CCE (Kubernetes)

| ID | Check | Severidad |
|----|-------|-----------|
| CCE-01 | Cluster con API endpoint publico | High |
| CCE-02 | Version Kubernetes desactualizada (<1.25) | Medium |

### CBR (Cloud Backup)

| ID | Check | Severidad |
|----|-------|-----------|
| CBR-01 | Vault sin recursos asociados | Low |
| CBR-02 | Politica de backup con retencion insuficiente | Medium |

### VPN

| ID | Check | Severidad |
|----|-------|-----------|
| VPN-01 | Conexion VPN con cifrado debil (DES/3DES) | High |

### DNS

| ID | Check | Severidad |
|----|-------|-----------|
| DNS-01 | Zona DNS publica (revision de registros) | Low |

### SFS (File System)

| ID | Check | Severidad |
|----|-------|-----------|
| SFS-01 | File system sin cifrado | Medium |

### FunctionGraph

| ID | Check | Severidad |
|----|-------|-----------|
| FG-01 | Funcion sin VPC (acceso directo a internet) | Medium |

### Cloud Eye (CES)

| ID | Check | Severidad |
|----|-------|-----------|
| CES-01 | Sin alarmas de monitoreo configuradas | Medium |

### LTS (Log Tank)

| ID | Check | Severidad |
|----|-------|-----------|
| LTS-02 | Retencion de logs menor a 30 dias | Medium |

### Config/RMS

| ID | Check | Severidad |
|----|-------|-----------|
| CFG-02 | Sin reglas de compliance configuradas | Medium |

### BMS (Bare Metal)

| ID | Check | Severidad |
|----|-------|-----------|
| BMS-01 | BMS con IP publica directa | Medium |
| BMS-02 | BMS con security group default | Low |

### IMS (Imagenes)

| ID | Check | Severidad |
|----|-------|-----------|
| IMS-01 | Imagen compartida publicamente | High |
| IMS-02 | Imagen privada antigua (>365 dias) | Low |

### TMS (Tags)

| ID | Check | Severidad |
|----|-------|-----------|
| TMS-01 | Sin tags predefinidos (sin gobernanza) | Low |

### SMN (Notificaciones)

| ID | Check | Severidad |
|----|-------|-----------|
| SMN-01 | Topicos de notificacion configurados | Low |

## Soporte de Regiones Custom

El scanner soporta regiones que no estan registradas en el SDK de Huawei Cloud (como `sa-argentina-1` Buenos Aires). El mecanismo es:

1. Intenta `with_region()` (regiones estandar registradas en el SDK)
2. Si la region no esta registrada, usa `with_endpoint()` construyendo la URL: `https://SERVICE.REGION.myhuaweicloud.com`

Esto permite escanear cualquier region futura sin necesidad de actualizar el SDK.

## Dashboard HTML Interactivo

El reporte principal es un dashboard HTML estatico (single-file, sin servidor) inspirado en AWS Service Screener. Se genera como `output/index.html` y se abre directamente en el navegador.

### Arquitectura del Dashboard

- **Single Page Application** con navegacion interna via JavaScript
- **Chart.js** para graficos interactivos (doughnut de severidad, barras por servicio)
- **Diseño responsivo** con sidebar colapsable en mobile
- **Datos embebidos** como JSON dentro del HTML (portable, no requiere server)

### Paginas y Secciones

| Pagina | Descripcion |
|--------|-------------|
| **Home (INDEX)** | Vista ejecutiva con KPIs, graficos y cards de servicios |
| **Findings** | Tabla completa de hallazgos con filtros, busqueda y export |
| **Servicio (detalle)** | Vista drill-down por servicio con checks y recursos individuales |

### Elementos Visuales

- **Stat Cards** (KPIs): Services Scanned, Total Checks, Failed Findings, Passed, Critical+High, Errors
- **Graficos**: Doughnut de severidad + Barras por servicio (solo findings fallidos)
- **Service Cards**: Grid clickeable para navegar al detalle de cada servicio
- **Tabla de Findings**: Ordenable, filtrable por servicio/severidad/status, con busqueda full-text
- **Resource Cards**: En la vista detalle, cada recurso muestra sus checks con iconos pass/fail
- **Barras de progreso**: En el summary, barras con % por severidad

### Paleta de Colores

| Elemento | Color | Codigo |
|----------|-------|--------|
| Sidebar | Dark Navy | `#232f3e` |
| Headers de seccion | Yellow-Gold | `#f0ad4e` |
| Critical | Purple | `#8e44ad` |
| High/Fail | Red | `#e74c3c` |
| Medium | Amber | `#f0ad4e` |
| Low | Cyan | `#5bc0de` |
| Pass/Info | Green | `#27ae60` / `#5cb85c` |
| Links/Active | Blue | `#0073bb` |

### Interactividad

- Filtros combinados (servicio + severidad + status)
- Busqueda full-text en tiempo real
- Ordenamiento por columna (click en header)
- Secciones colapsables (click en header dorado)
- Tabs (Findings / Suppressed)
- Export CSV desde el navegador
- Copy to clipboard de la tabla
- Filtro por cuenta (multi-account)
- Sidebar responsive (hamburger menu en mobile)

Para una guia paso a paso de como navegar el dashboard, ver [GUIA_DASHBOARD.md](GUIA_DASHBOARD.md).

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
