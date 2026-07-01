# Instrucciones - Huawei Cloud Security Scanner

Guia completa paso a paso para configurar y ejecutar el scanner de seguridad en cuentas de Huawei Cloud.

---

## Tabla de Contenidos

1. [Requisitos Previos](#1-requisitos-previos)
2. [Instalacion](#2-instalacion)
3. [Configuracion de Credenciales (Variables de Entorno)](#3-configuracion-de-credenciales)
4. [Configuracion de Regiones (config.yaml)](#4-configuracion-de-regiones)
5. [Ejecucion del Scanner](#5-ejecucion-del-scanner)
6. [Visualizacion de Reportes](#6-visualizacion-de-reportes)
7. [Exportacion de Informes](#7-exportacion-de-informes)
8. [Agregar Nuevas Regiones](#8-agregar-nuevas-regiones)
9. [Regiones Custom/Locales](#9-regiones-customlocales)
10. [Modo Multi Account](#10-modo-multi-account)
11. [Scanners Disponibles](#11-scanners-disponibles)
12. [Sobre Recursos Creados](#12-sobre-recursos-creados)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Requisitos Previos

- Python 3.9 o superior
- Cuenta de Huawei Cloud con acceso a la consola
- Access Key (AK) y Secret Key (SK) con permisos de lectura
- Conectividad a internet (para acceder a las APIs de Huawei Cloud)

### Permisos del usuario IAM

La forma mas simple es asignar el rol **Tenant Guest** + **IAM ReadOnlyAccess** al usuario:

| Rol | Que permite |
|-----|------------|
| `Tenant Guest` | Lectura de todos los servicios (VPC, ECS, OBS, CTS, ELB) |
| `IAM ReadOnlyAccess` | Lectura de usuarios, grupos, politicas, MFA |

### Como crear el usuario IAM para el scanner

**Paso 1: Crear un grupo de usuarios**

1. Ingresa a la consola de Huawei Cloud > **IAM** > **User Groups**
2. Click en **Create User Group**
3. Nombre: `security-auditors`
4. Click en **OK**

**Paso 2: Asignar permisos al grupo**

1. En la lista de grupos, click en `security-auditors`
2. Tab **Permissions** > **Authorize**
3. Buscar y seleccionar: **Tenant Guest** y **IAM ReadOnlyAccess**
4. Seleccionar el **Scope**: **All resources**
5. Click en **OK**

**Paso 3: Crear el usuario IAM**

1. Ve a **IAM** > **Users** > **Create User**
2. Configurar:
   - **Username**: `security-scanner`
   - **Access Type**: marcar **Programmatic access** (genera AK/SK)
   - **Console access**: desmarcar (no necesita acceso a consola)
3. Click en **Next**
4. Asignar al grupo `security-auditors`
5. Click en **Create**
6. **Descargar las credenciales** (AK/SK) - se muestran una sola vez

---

## 2. Instalacion

### Clonar el repositorio

```bash
git clone https://github.com/daianape/huawei-cloud-security-scanner.git
cd huawei-cloud-security-scanner
```

### Crear entorno virtual

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / Mac
python3 -m venv venv
source venv/bin/activate
```

### Instalar dependencias

```bash
pip install -r requirements.txt
```

---

## 3. Configuracion de Credenciales

Las credenciales **NO van en ningun archivo**. Se configuran como variables de entorno antes de ejecutar el scanner. Al cerrar la terminal, desaparecen.

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

### Donde obtener cada valor

| Variable | Donde encontrarla |
|----------|------------------|
| `HWCLOUD_AK` | Archivo CSV descargado al crear el Access Key |
| `HWCLOUD_SK` | Archivo CSV descargado al crear el Access Key |

> El `domain_id` y los `project_id` van en el archivo `config/config.yaml` (no son secretos, son identificadores publicos de tu cuenta).

### Por que variables de entorno?

- No quedan escritas en ningun archivo del proyecto
- No se pueden commitear accidentalmente a Git
- Desaparecen al cerrar la terminal
- Es el metodo recomendado por la industria para credenciales

---

## 4. Configuracion de Regiones

El archivo `config/config.yaml` contiene la configuracion de regiones, scanners y output. **No contiene credenciales.**

### Paso 1: Copiar el archivo de ejemplo

```bash
copy config\config.yaml.example config\config.yaml
```

### Paso 2: Obtener los Project IDs

1. Ingresa a la consola de Huawei Cloud
2. Click en tu nombre de usuario > **My Credentials**
3. Seccion **API Credentials** - veras una tabla con Region y Project ID
4. Copiar el Project ID de cada region que quieras escanear

### Paso 3: Completar el config.yaml

Editar `config/config.yaml` y completar:

1. El `domain_id` (Account ID) — una sola vez
2. Los `project_id` de cada region que quieras escanear

La primera region con `project_id` completado se usa como region principal por defecto.

**Las regiones con `project_id` vacio se ignoran automaticamente.**

Ejemplo con regiones completadas:

```yaml
mode: "single"
domain_id: "2e057fc2297549029c9e0dc90ec47251"

regions:
  - region: "la-south-2"
    project_id: "f521b5fa85c44e718d99e998d4ce7ea6"    # completada - se escanea
  - region: "la-north-2"
    project_id: "49137fe2a37d45ecb95921999e37b14a"    # completada - se escanea
  - region: "ap-southeast-1"
    project_id: "06791a33aed54779b2c29e3db294e227"    # completada - se escanea
  - region: "af-south-1"
    project_id: ""                                     # vacia - se ignora

scanners:
  iam: true
  vpc: true
  ecs: true
  obs: true
  cts: true
  elb: true

output:
  directory: "./output"
  formats:
    - html
    - json
```

### Comportamiento segun el comando

| Comando | Que escanea |
|---------|------------|
| `python main.py scan --no-verify-ssl` | Solo la region principal (`region: "la-south-2"`) |
| `python main.py scan --no-verify-ssl --regions all` | Todas las regiones con project_id completado |
| `python main.py scan --no-verify-ssl --regions la-south-2,la-north-2` | Solo las regiones indicadas |

---

## 5. Ejecucion del Scanner

### Flujo completo

```bash
# 1. Activar entorno virtual
venv\Scripts\activate

# 2. Configurar credenciales (hacer esto cada vez que abras una terminal nueva)
set HWCLOUD_AK=tu_access_key
set HWCLOUD_SK=tu_secret_key

# 3. Ejecutar el scan
python main.py scan --no-verify-ssl
```

### Opciones de ejecucion

```bash
# Scan basico (region principal del config)
python main.py scan --no-verify-ssl

# Scan de una region especifica
python main.py scan --no-verify-ssl --regions la-south-2

# Scan de multiples regiones
python main.py scan --no-verify-ssl --regions la-south-2,la-north-2,ap-southeast-1

# Scan de TODAS las regiones configuradas (con project_id)
python main.py scan --no-verify-ssl --regions all

# Solo scanners especificos (cualquier combinacion de los 28 scanners)
python main.py scan --no-verify-ssl --scanners iam,vpc,rds,kms,cce

# Elegir formatos de salida
python main.py scan --no-verify-ssl --format html,json,csv

# Combinar opciones
python main.py scan --no-verify-ssl --regions all --scanners iam,vpc,rds --format html,csv

# Modo verbose (mas detalle)
python main.py scan --no-verify-ssl --verbose
```

### Otros comandos

```bash
# Listar regiones disponibles
python main.py list-regions

# Listar scanners disponibles
python main.py list-scanners

# Validar configuracion
python main.py validate

# Ver version
python main.py --version
```

### Nota sobre --no-verify-ssl

Este flag es necesario si tu red corporativa usa un proxy que intercepta SSL (certificado self-signed). Si estas en una red sin proxy, podes omitirlo.

---

## 6. Visualizacion de Reportes

Despues de ejecutar el scan, abrir el dashboard HTML:

```bash
# Windows
start output\index.html

# Linux
xdg-open output/index.html

# Mac
open output/index.html
```

El dashboard incluye:

- **Pagina Home**: resumen de severidades, cards por servicio, graficos
- **Pagina Findings**: tabla completa filtrable por severidad, status y servicio
- **Paginas por Servicio**: hallazgos detallados de cada servicio
- **Selector de cuentas**: dropdown para filtrar por cuenta (multi-account)

---

## 7. Exportacion de Informes

| Formato | Archivo | Uso |
|---------|---------|-----|
| HTML | `output/index.html` | Dashboard visual interactivo |
| JSON | `output/scan_report_FECHA.json` | Integracion con SIEM, automatizacion |
| CSV | `output/scan_findings_FECHA.csv` | Analisis en Excel, filtros, pivots |

El config.yaml.example ya incluye los 3 formatos por defecto. Si solo queres algunos, editá la seccion `output.formats`:

```yaml
output:
  directory: "./output"
  formats:
    - html
    - json
    - csv
```

Tambien podes elegir formatos desde la linea de comandos (override del config):

```bash
# Solo HTML
python main.py scan --no-verify-ssl --format html

# Solo CSV (rapido, sin generar dashboard)
python main.py scan --no-verify-ssl --format csv

# Todos
python main.py scan --no-verify-ssl --format html,json,csv
```

### CSV en Excel

El archivo CSV se genera con encoding UTF-8 BOM, compatible con Excel. Columnas:

- account_name, account_id, region
- service, category, check_id, check_title
- severity, status
- description, resource_id, resource_name
- remediation, reference_url, timestamp

---

## 8. Agregar Nuevas Regiones

Si Huawei Cloud habilita una nueva region para tu cuenta:

**Paso 1:** Ir a Huawei Console > My Credentials > API Credentials

**Paso 2:** Copiar el Project ID de la nueva region

**Paso 3:** Editar `config/config.yaml` y agregar una entrada en la seccion `regions`:

```yaml
regions:
  # ... regiones existentes ...
  - region: "nuevo-codigo-region"
    project_id: "el-project-id-de-esa-region"
```

**Paso 4:** Ejecutar el scan incluyendo la nueva region:

```bash
python main.py scan --no-verify-ssl --regions nuevo-codigo-region
```

O escanear todas:

```bash
python main.py scan --no-verify-ssl --regions all
```

### Como saber los codigos de region

```bash
python main.py list-regions
```

O consultar: https://developer.huaweicloud.com/intl/en-us/endpoint

---

## 9. Regiones Custom/Locales

El scanner soporta regiones que no estan registradas oficialmente en el SDK de Huawei Cloud.

### Como funciona

El sistema `_build_client` en `base_scanner.py` implementa un fallback:
1. Intenta conectar via `with_region()` (regiones estandar del SDK)
2. Si la region no existe en el SDK, usa `with_endpoint()` con la URL: `https://SERVICE.REGION.myhuaweicloud.com`

### Ejemplo: Buenos Aires (sa-argentina-1)

En `config/config.yaml`:
```yaml
regions:
  - region: "sa-argentina-1"
    project_id: "tu-project-id-de-buenos-aires"
```

Ejecutar normalmente:
```bash
python main.py scan --no-verify-ssl --regions sa-argentina-1
```

El scanner detectara automaticamente que `sa-argentina-1` no esta en el registro del SDK y usara el endpoint explicito.

### Agregar cualquier region futura

Si Huawei Cloud habilita una nueva region (ej: `xx-nuevo-1`):
1. Obtener el Project ID de esa region
2. Agregarlo al `config.yaml`
3. Ejecutar el scan - funciona sin actualizar el SDK

---

## 10. Modo Multi Account

Para escanear multiples cuentas de Huawei Cloud desde una cuenta central.

### Concepto: IAM Agencies

Se crea una **Agency** en cada cuenta target que delega permisos de lectura a la cuenta de auditoria.

### Configuracion

En `config.yaml` cambiar `mode: "multi"` y agregar la seccion `multi_account`. Ver `config.yaml.example` para el formato completo.

Las credenciales de la cuenta management tambien van por variables de entorno (`HWCLOUD_AK` / `HWCLOUD_SK`).

---

## 11. Scanners Disponibles (28)

El scanner cubre los siguientes servicios de Huawei Cloud:

### Categoria: Identidad y Acceso

| Scanner | Nombre CLI | Descripcion |
|---------|-----------|-------------|
| IAM | `iam` | Usuarios, MFA, access keys, password policy, permisos admin |
| Identity Center | `identity-center` | Permission sets, duracion de sesiones |
| KMS/DEW | `kms` | Rotacion de CMKs, keys deshabilitadas, pendientes de eliminacion |
| TMS | `tms` | Tags predefinidos para gobernanza |

### Categoria: Red

| Scanner | Nombre CLI | Descripcion |
|---------|-----------|-------------|
| VPC | `vpc` | Security groups, puertos abiertos, egress sin restriccion |
| NAT Gateway | `nat` | Reglas DNAT exponiendo puertos sensibles (SSH, RDP, DBs) |
| EIP | `eip` | IPs elasticas no asociadas |
| WAF | `waf` | Dominios sin proteccion, modo deteccion |
| Cloud Firewall | `cfw` | Firewall no desplegado o inactivo |
| VPN | `vpn` | Cifrado debil (DES/3DES) en IKE/IPSec |
| DNS | `dns` | Zonas publicas que pueden exponer infraestructura |
| ELB | `elb` | Listeners sin HTTPS, version TLS obsoleta |

### Categoria: Computo

| Scanner | Nombre CLI | Descripcion |
|---------|-----------|-------------|
| ECS | `ecs` | Instancias con IP publica, SG default |
| CCE | `cce` | API Kubernetes publica, version K8s desactualizada |
| BMS | `bms` | Bare Metal con IP publica, SG default |
| FunctionGraph | `functiongraph` | Funciones sin VPC (acceso directo a internet) |
| IMS | `ims` | Imagenes publicas, imagenes antiguas (>365 dias) |

### Categoria: Almacenamiento

| Scanner | Nombre CLI | Descripcion |
|---------|-----------|-------------|
| OBS | `obs` | Buckets publicos (lectura/escritura), sin cifrado, sin logging |
| RDS | `rds` | Base de datos con IP publica, sin backup, sin SSL |
| DCS | `dcs` | Redis sin password, acceso publico, sin SSL |
| EVS | `evs` | Volumenes sin cifrado en reposo |
| SFS Turbo | `sfs` | File systems sin cifrado |
| CBR | `cbr` | Vaults vacios, retencion de backup insuficiente |

### Categoria: Logging y Monitoreo

| Scanner | Nombre CLI | Descripcion |
|---------|-----------|-------------|
| CTS | `cts` | Cloud Trace deshabilitado, sin almacenamiento OBS |
| Cloud Eye | `ces` | Sin alarmas de monitoreo |
| LTS | `lts` | Retencion de logs menor a 30 dias |
| Config/RMS | `config` | Sin reglas de compliance |
| SMN | `smn` | Topicos de notificacion |

### Ejecutar scanners selectivos

```bash
# Solo scanners de red
python main.py scan --no-verify-ssl --scanners vpc,nat,eip,waf,cfw,vpn,dns,elb

# Solo almacenamiento
python main.py scan --no-verify-ssl --scanners obs,rds,dcs,evs,sfs,cbr

# Solo identidad
python main.py scan --no-verify-ssl --scanners iam,identity-center,kms,tms

# Scan minimo rapido
python main.py scan --no-verify-ssl --scanners iam,vpc,ecs
```

---

## 12. Sobre Recursos Creados

### Esta herramienta NO crea ningun recurso

El scanner es **100% de solo lectura**. No ejecuta ninguna operacion de Create, Update o Delete.

- **En tu cuenta de Huawei Cloud**: no queda nada
- **En tu maquina local**: se generan reportes en `output/`
- **Logs de auditoria (CTS)**: las llamadas API quedan registradas como operaciones de lectura

### Para eliminar despues del assessment

- **Borrar reportes locales**: eliminar la carpeta `output/`
- **En modo Multi Account**: eliminar las Agencies creadas en IAM > Agencies

---

## 13. Troubleshooting

### Error: "Credenciales no configuradas"

```
Causa: No se configuraron las variables de entorno HWCLOUD_AK / HWCLOUD_SK.

Solucion:
  set HWCLOUD_AK=tu_access_key
  set HWCLOUD_SK=tu_secret_key
```

### Error: "SSL: CERTIFICATE_VERIFY_FAILED"

```
Causa: Red corporativa con proxy SSL.

Solucion: Agregar --no-verify-ssl al comando
  python main.py scan --no-verify-ssl
```

### Error: "failed to reach the limit, forbidden"

```
Causa: Rate limiting por demasiadas llamadas API en poco tiempo.

Solucion: Esperar 15-30 minutos y volver a ejecutar.
El scanner tiene delays entre llamadas para evitar esto.
```

### Error: "not authorized to perform"

```
Causa: El usuario IAM no tiene permisos suficientes.

Solucion: Asignar Tenant Guest + IAM ReadOnlyAccess al grupo del usuario.
```

### Error: "get token error, status:400"

```
Causa: El project_id no corresponde a la region configurada.

Solucion: Verificar en My Credentials que el project_id coincide
con la region que estas escaneando.
```

### Las credenciales se pierden al cerrar la terminal

```
Esto es intencional (seguridad). Cada vez que abras una terminal nueva,
volver a configurar:
  set HWCLOUD_AK=tu_access_key
  set HWCLOUD_SK=tu_secret_key
```

### Warning: "Region 'xxx' not in SDK registry, using explicit endpoint"

```
Causa: La region no esta registrada en el SDK de Huawei (es custom/local).

Esto NO es un error. El scanner usa automaticamente un endpoint explicito.
El scan continuara normalmente.
```

### Scanner reporta "SDK No Disponible"

```
Causa: Falta instalar el SDK del servicio.

Solucion: pip install -r requirements.txt
O instalar el SDK especifico, ej: pip install huaweicloudsdkrds
```

---

## Contacto

Para reportar issues o contribuir: https://github.com/daianape/huawei-cloud-security-scanner/issues
