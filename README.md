# Huawei Cloud Security Scanner

Herramienta de evaluacion de seguridad para cuentas de Huawei Cloud. Escanea configuraciones de 28 servicios, genera hallazgos con niveles de severidad y produce un dashboard HTML interactivo, reportes JSON y CSV.

## Caracteristicas

- **28 scanners de seguridad** cubriendo IAM, Networking, Compute, Storage, Databases, Containers, Security y Governance
- **Servicios globales vs regionales**: IAM, Identity Center, TMS y Config se escanean una sola vez (no se duplican por region)
- **Multi Region**: escanea una region, varias, o todas las configuradas en una sola ejecucion
- **Multi Account**: soporte para multiples cuentas usando IAM Agencies
- **Regiones custom**: soporta regiones locales no registradas en el SDK (como sa-argentina-1)
- **Dashboard HTML interactivo**: estilo AWS Service Screener con sidebar navy, stat cards coloridas, graficos, check cards por servicio y tablas con filtros avanzados
- **Multiples formatos**: HTML, JSON, CSV (compatible con Excel)
- **Credenciales seguras**: AK/SK por variables de entorno, nunca en archivos
- **Solo lectura**: no crea, modifica ni elimina ningun recurso
- **Anti rate-limit**: delays automaticos entre checks y regiones, retry en throttling

## Inicio Rapido

```bash
# 1. Clonar e instalar
git clone https://github.com/daianape/huawei-cloud-security-scanner.git
cd huawei-cloud-security-scanner
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# 2. Configurar regiones (config.yaml)
copy config\config.yaml.example config\config.yaml
# Editar: completar domain_id y project_ids de tus regiones

# 3. Configurar credenciales (variables de entorno)
set HWCLOUD_AK=tu_access_key
set HWCLOUD_SK=tu_secret_key

# 4. Ejecutar
python main.py scan --no-verify-ssl
```

## Autenticacion

Las credenciales se pasan **exclusivamente por variables de entorno**:

| Variable | Descripcion | Obligatoria |
|----------|-------------|-------------|
| `HWCLOUD_AK` | Access Key | Si |
| `HWCLOUD_SK` | Secret Key | Si |

El `domain_id` y los `project_id` van en `config/config.yaml` (identificadores publicos, no secretos).

## Comandos CLI

### Sobre `--no-verify-ssl`

Deshabilita verificacion de certificados SSL. Necesario si tu red corporativa tiene un proxy que intercepta HTTPS. Si no ves errores de SSL, podes omitirlo.

### Ejemplos

```bash
# Scan region principal (primera con project_id en config)
python main.py scan --no-verify-ssl

# Scan region especifica
python main.py scan --no-verify-ssl --regions la-south-2

# Scan multiples regiones
python main.py scan --no-verify-ssl --regions la-south-2,la-north-2,sa-argentina-1

# Scan TODAS las regiones con project_id configurado
python main.py scan --no-verify-ssl --regions all

# Solo scanners especificos
python main.py scan --no-verify-ssl --scanners vpc,ecs,rds

# Elegir formatos de salida
python main.py scan --no-verify-ssl --format html,json,csv

# Sin proxy corporativo
python main.py scan --regions all

# Listar regiones / scanners
python main.py list-regions
python main.py list-scanners

# Validar configuracion
python main.py validate
```

## Scanners Disponibles (28)

### Servicios Globales (se escanean una sola vez)

| ID | Servicio | Checks |
|----|----------|--------|
| IAM | Identity and Access Management | MFA, key rotation, password policy, admin perms, inactive users, multiple keys |
| IDC | IAM Identity Center | Permission sets, session duration |
| TMS | Tag Management Service | Tags predefinidos para governance |
| CFG | Config/RMS | Reglas de compliance configuradas |

### Servicios Regionales (se escanean por cada region)

**Networking:**

| ID | Servicio | Checks |
|----|----------|--------|
| VPC | Virtual Private Cloud | Puertos sensibles abiertos, egress irrestricto, allow-all, rangos amplios |
| ELB | Elastic Load Balance | Listeners sin HTTPS, TLS version obsoleta |
| NAT | NAT Gateway | DNAT exponiendo puertos sensibles |
| EIP | Elastic IP | IPs sin asociar |
| WAF | Web Application Firewall | Dominios sin proteccion, modo solo deteccion |
| CFW | Cloud Firewall | Firewall no desplegado/inactivo |
| VPN | Virtual Private Network | Cifrado debil (DES/3DES) |
| DNS | Domain Name Service | Zonas publicas |

**Compute:**

| ID | Servicio | Checks |
|----|----------|--------|
| ECS | Elastic Cloud Server | IP publica directa, security group default |
| BMS | Bare Metal Server | IP publica, security group default |
| CCE | Cloud Container Engine | API publica, K8s desactualizado |
| FG | FunctionGraph | Funciones sin VPC |
| IMS | Image Management | Imagenes publicas, imagenes antiguas (>365 dias) |

**Storage:**

| ID | Servicio | Checks |
|----|----------|--------|
| OBS | Object Storage Service | Buckets publicos, sin cifrado, sin logging |
| EVS | Elastic Volume Service | Volumenes sin cifrado |
| SFS | Scalable File Service | File systems sin cifrado |
| CBR | Cloud Backup and Recovery | Vaults vacios, retencion insuficiente |

**Databases:**

| ID | Servicio | Checks |
|----|----------|--------|
| RDS | Relational Database Service | Acceso publico, sin backups, sin SSL |
| DCS | Distributed Cache (Redis) | Sin password, acceso publico, sin SSL |

**Logging & Monitoring:**

| ID | Servicio | Checks |
|----|----------|--------|
| CTS | Cloud Trace Service | Tracker deshabilitado, sin OBS storage |
| CES | Cloud Eye | Sin alarmas configuradas |
| LTS | Log Tank Service | Retencion de logs corta |
| SMN | Simple Message Notification | Topics de alertas |

**Security:**

| ID | Servicio | Checks |
|----|----------|--------|
| KMS | Key Management Service | Keys sin rotacion, deshabilitadas, pendientes de eliminacion |

## Output

![Dashboard preview](docs/images/dashboard-home-full.png)

| Formato | Archivo | Uso |
|---------|---------|-----|
| HTML | `output/index.html` | Dashboard visual interactivo (estilo AWS Service Screener) |
| JSON | `output/scan_report_FECHA.json` | Integracion SIEM, automatizacion |
| CSV | `output/scan_findings_FECHA.csv` | Excel, filtros, pivot tables |

## Documentacion Detallada

Ver [INSTRUCCIONES.md](INSTRUCCIONES.md) para:
- Guia paso a paso completa
- Como crear el usuario IAM con permisos
- Como agregar nuevas regiones
- Modo Multi Account
- Troubleshooting

## Nota sobre Recursos

**Esta herramienta es 100% de solo lectura.** No crea, modifica ni elimina recursos en tu cuenta.

## Licencia

MIT License
