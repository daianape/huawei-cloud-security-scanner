# Instrucciones - Huawei Cloud Security Scanner

Guia completa paso a paso para configurar y ejecutar el scanner de seguridad en cuentas de Huawei Cloud.

---

## Tabla de Contenidos

1. [Requisitos Previos](#1-requisitos-previos)
2. [Instalacion](#2-instalacion)
3. [Configuracion de Credenciales](#3-configuracion-de-credenciales)
4. [Configuracion de Regiones](#4-configuracion-de-regiones)
5. [Ejecucion del Scanner](#5-ejecucion-del-scanner)
6. [Servicios Globales vs Regionales](#6-servicios-globales-vs-regionales)
7. [Exportacion de Informes](#7-exportacion-de-informes)
8. [Agregar Nuevas Regiones](#8-agregar-nuevas-regiones)
9. [Modo Multi Account](#9-modo-multi-account)
10. [Sobre Recursos Creados](#10-sobre-recursos-creados)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Requisitos Previos

- Python 3.9 o superior
- Cuenta de Huawei Cloud con acceso a la consola
- Access Key (AK) y Secret Key (SK)
- Conectividad a internet

### Permisos del usuario IAM

Asignar los roles **Tenant Guest** + **IAM ReadOnlyAccess** al usuario:

| Rol | Que permite |
|-----|------------|
| `Tenant Guest` | Lectura de todos los servicios regionales (VPC, ECS, OBS, etc.) |
| `IAM ReadOnlyAccess` | Lectura de usuarios, grupos, politicas, MFA |

### Como crear el usuario IAM

1. **IAM > User Groups > Create User Group** → nombre: `security-auditors`
2. **Permissions > Authorize** → seleccionar `Tenant Guest` + `IAM ReadOnlyAccess` → Scope: All resources
3. **IAM > Users > Create User** → username: `security-scanner`, Access Type: Programmatic access
4. Asignar al grupo `security-auditors`
5. **Descargar las credenciales** (AK/SK) — se muestran una sola vez

---

## 2. Instalacion

```bash
git clone https://github.com/daianape/huawei-cloud-security-scanner.git
cd huawei-cloud-security-scanner
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/Mac
pip install -r requirements.txt
```

---

## 3. Configuracion de Credenciales

Las credenciales **NO van en ningun archivo**. Se configuran como variables de entorno:

### Windows (CMD)

```cmd
set HWCLOUD_AK=tu_access_key
set HWCLOUD_SK=tu_secret_key
```

### Windows (PowerShell)

```powershell
$env:HWCLOUD_AK="tu_access_key"
$env:HWCLOUD_SK="tu_secret_key"
```

### Linux / Mac

```bash
export HWCLOUD_AK=tu_access_key
export HWCLOUD_SK=tu_secret_key
```

> Las credenciales desaparecen al cerrar la terminal. Hay que configurarlas cada vez que se abre una terminal nueva.

---

## 4. Configuracion de Regiones

El archivo `config/config.yaml` contiene regiones, scanners y output. **No contiene credenciales.**

### Crear el archivo

```bash
copy config\config.yaml.example config\config.yaml
```

### Completar el config.yaml

Editar y completar:

1. El `domain_id` (Account ID) — una sola vez, obtener de My Credentials
2. Los `project_id` de cada region que quieras escanear — obtener de My Credentials > API Credentials

**Las regiones con `project_id` vacio se ignoran automaticamente.**

La primera region con `project_id` completado se usa como default.

```yaml
mode: "single"
domain_id: "tu-account-id"

regions:
  - region: "la-south-2"
    project_id: "abc123..."       # completada - se escanea
  - region: "la-north-2"
    project_id: "def456..."       # completada - se escanea
  - region: "sa-argentina-1"
    project_id: "ghi789..."       # completada - se escanea
  - region: "af-south-1"
    project_id: ""                 # vacia - se ignora

scanners:
  iam: true
  vpc: true
  ecs: true
  obs: true
  cts: true
  elb: true
  identity-center: true
  rds: true
  dcs: true
  nat: true
  eip: true
  waf: true
  cfw: true
  evs: true
  kms: true
  cce: true
  cbr: true
  vpn: true
  dns: true
  sfs: true
  functiongraph: true
  ces: true
  lts: true
  config: true
  smn: true
  bms: true
  ims: true
  tms: true

output:
  directory: "./output"
  formats:
    - html
    - json
    - csv
```

---

## 5. Ejecucion del Scanner

### Flujo completo

```bash
# 1. Activar entorno virtual
venv\Scripts\activate

# 2. Configurar credenciales
set HWCLOUD_AK=tu_access_key
set HWCLOUD_SK=tu_secret_key

# 3. Ejecutar
python main.py scan --no-verify-ssl
```

### Opciones de ejecucion

```bash
# Scan region principal (primera con project_id)
python main.py scan --no-verify-ssl

# Scan region especifica
python main.py scan --no-verify-ssl --regions la-south-2

# Scan multiples regiones
python main.py scan --no-verify-ssl --regions la-south-2,la-north-2,sa-argentina-1

# Scan TODAS las regiones configuradas
python main.py scan --no-verify-ssl --regions all

# Solo scanners especificos
python main.py scan --no-verify-ssl --scanners vpc,ecs,rds

# Elegir formatos de salida
python main.py scan --no-verify-ssl --format html,json,csv

# Sin proxy corporativo (no necesita --no-verify-ssl)
python main.py scan --regions all

# Modo verbose
python main.py scan --no-verify-ssl --verbose
```

### Otros comandos

```bash
python main.py list-regions      # Ver regiones disponibles
python main.py list-scanners     # Ver scanners disponibles
python main.py validate          # Validar configuracion
python main.py --version         # Ver version
```

### Sobre --no-verify-ssl

Necesario si tu red corporativa tiene un proxy que intercepta HTTPS (error "self-signed certificate"). Si estas en una red sin proxy, podes omitirlo.

### Comportamiento segun comando

| Comando | Que escanea |
|---------|------------|
| `python main.py scan` | Region principal + servicios globales |
| `python main.py scan --regions all` | Todas las regiones con project_id + globales |
| `python main.py scan --regions la-south-2,la-north-2` | Solo esas regiones + globales |

---

## 6. Servicios Globales vs Regionales

El scanner diferencia entre servicios **globales** (independientes de region) y **regionales** (tienen recursos distintos por region):

### Servicios Globales (se escanean UNA sola vez)

- **IAM** — usuarios, MFA, access keys, password policy
- **IAM Identity Center** — permission sets, sesiones
- **TMS** — tags predefinidos
- **Config/RMS** — reglas de compliance

Estos servicios aparecen en el reporte con `region: Global` y no se repiten por cada region.

### Servicios Regionales (se escanean POR CADA region configurada)

VPC, ECS, ELB, OBS, CTS, NAT, EIP, WAF, CFW, EVS, KMS, CCE, RDS, DCS, CBR, VPN, DNS, SFS, FunctionGraph, CES, LTS, SMN, BMS, IMS.

Cada region puede tener recursos diferentes, por eso se escanean individualmente.

---

## 7. Exportacion de Informes

| Formato | Archivo | Uso |
|---------|---------|-----|
| HTML | `output/index.html` | Dashboard visual interactivo |
| JSON | `output/scan_report_FECHA.json` | Integracion con SIEM, automatizacion |
| CSV | `output/scan_findings_FECHA.csv` | Analisis en Excel, filtros, pivots |

Los 3 formatos se generan por defecto. Para elegir:

```bash
python main.py scan --no-verify-ssl --format csv         # Solo CSV
python main.py scan --no-verify-ssl --format html,csv    # Sin JSON
```

### CSV en Excel

El archivo CSV se genera con encoding UTF-8 BOM, compatible con Excel. Columnas: account_name, account_id, region, service, category, check_id, check_title, severity, status, description, resource_id, resource_name, remediation, reference_url, timestamp.

### Abrir el dashboard

```bash
start output\index.html      # Windows
open output/index.html       # Mac
xdg-open output/index.html   # Linux
```

---

## 8. Agregar Nuevas Regiones

1. Ir a **Huawei Console > My Credentials > API Credentials**
2. Copiar el Project ID de la nueva region
3. Editar `config/config.yaml`, agregar en la seccion `regions`:

```yaml
  - region: "nuevo-codigo-region"
    project_id: "el-project-id"
```

4. Ejecutar: `python main.py scan --no-verify-ssl --regions nuevo-codigo-region`

> Las regiones no registradas en el SDK (como sa-argentina-1) funcionan automaticamente via endpoint explicito.

---

## 9. Modo Multi Account

Para escanear multiples cuentas, crear una **Agency** en cada cuenta target y configurar `mode: "multi"` en el config. Ver `config.yaml.example` para el formato completo.

---

## 10. Sobre Recursos Creados

**Esta herramienta NO crea ningun recurso.** Es 100% solo lectura (GET/LIST).

- En Huawei Cloud: no queda nada
- En tu maquina: se generan reportes en `output/`
- En CTS: las llamadas API quedan como operaciones de lectura (normal)

---

## 11. Troubleshooting

### "Credenciales no configuradas"
```
Solucion: set HWCLOUD_AK=tu_access_key && set HWCLOUD_SK=tu_secret_key
```

### "SSL: CERTIFICATE_VERIFY_FAILED"
```
Solucion: Agregar --no-verify-ssl al comando
```

### "failed to reach the limit, forbidden"
```
Causa: Rate limiting por muchas llamadas API.
Solucion: Esperar 15-30 minutos. El scanner tiene delays automaticos.
```

### "not authorized to perform"
```
Causa: Permisos insuficientes.
Solucion: Asignar Tenant Guest + IAM ReadOnlyAccess al usuario.
```

### "get token error, status:400"
```
Causa: El project_id no corresponde a la region.
Solucion: Verificar en My Credentials que cada project_id coincide con su region.
```

### "El SDK de [servicio] no esta instalado"
```
Causa: Algun paquete del requirements.txt no se instalo correctamente.

Solucion: Verificar e instalar manualmente:
  pip show huaweicloudsdkidentitycenter
  pip show huaweicloudsdkrms

Si dice "Package not found", instalar individualmente:
  pip install huaweicloudsdkidentitycenter huaweicloudsdkrms

O reinstalar todo:
  pip install -r requirements.txt --force-reinstall
```

### "Region not in SDK registry, using explicit endpoint"
```
Esto es informativo, no un error. El scanner usa endpoint directo para regiones
custom (como sa-argentina-1). Funciona normalmente.
```

### "Failed to resolve" (DNS error)
```
Causa: El servicio no existe en esa region (ej: WAF en sa-argentina-1).
Solucion: Normal, no todos los servicios estan en todas las regiones.
```

### Credenciales se pierden al cerrar la terminal
```
Intencional (seguridad). Configurar cada vez:
  set HWCLOUD_AK=tu_access_key
  set HWCLOUD_SK=tu_secret_key
```

---

## Contacto

Issues y contribuciones: https://github.com/daianape/huawei-cloud-security-scanner/issues
