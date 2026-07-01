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
9. [Modo Multi Account](#9-modo-multi-account)
10. [Sobre Recursos Creados](#10-sobre-recursos-creados)
11. [Troubleshooting](#11-troubleshooting)

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
set HWCLOUD_DOMAIN_ID=tu_domain_id
```

### Windows (PowerShell)

```powershell
$env:HWCLOUD_AK="tu_access_key"
$env:HWCLOUD_SK="tu_secret_key"
$env:HWCLOUD_DOMAIN_ID="tu_domain_id"
```

### Linux / Mac

```bash
export HWCLOUD_AK=tu_access_key
export HWCLOUD_SK=tu_secret_key
export HWCLOUD_DOMAIN_ID=tu_domain_id
```

### Donde obtener cada valor

| Variable | Donde encontrarla |
|----------|------------------|
| `HWCLOUD_AK` | Archivo CSV descargado al crear el Access Key |
| `HWCLOUD_SK` | Archivo CSV descargado al crear el Access Key |
| `HWCLOUD_DOMAIN_ID` | Huawei Console > My Credentials > Account ID |

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

1. El `domain_id` (Account ID)
2. El `project_id` de la region principal
3. Los `project_id` de cada region en la seccion `regions` que quieras escanear

**Las regiones con `project_id` vacio se ignoran automaticamente.** Solo completar las que tengan recursos.

Ejemplo con regiones completadas:

```yaml
mode: "single"
domain_id: "2e057fc2297549029c9e0dc90ec47251"
region: "la-south-2"
project_id: "f521b5fa85c44e718d99e998d4ce7ea6"

regions:
  - region: "la-south-2"
    project_id: "f521b5fa85c44e718d99e998d4ce7ea6"    # completada - se escanea
  - region: "la-north-2"
    project_id: "49137fe2a37d45ecb95921999e37b14a"    # completada - se escanea
  - region: "ap-southeast-1"
    project_id: "06791a33aed54779b2c29e3db294e227"    # completada - se escanea
  - region: "af-south-1"
    project_id: ""                                     # vacia - se ignora
  - region: "eu-west-0"
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
set HWCLOUD_DOMAIN_ID=tu_domain_id

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

# Solo scanners especificos
python main.py scan --no-verify-ssl --scanners iam,vpc

# Elegir formatos de salida
python main.py scan --no-verify-ssl --format html,json,csv

# Combinar opciones
python main.py scan --no-verify-ssl --regions all --scanners iam,vpc --format html,csv

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
| HTML | `output/index.html` | Dashboard visual |
| JSON | `output/scan_report_FECHA.json` | Integracion con SIEM |
| CSV | `output/scan_findings_FECHA.csv` | Analisis en Excel |

Para generar todos los formatos:

```bash
python main.py scan --no-verify-ssl --format html,json,csv
```

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

## 9. Modo Multi Account

Para escanear multiples cuentas de Huawei Cloud desde una cuenta central.

### Concepto: IAM Agencies

Se crea una **Agency** en cada cuenta target que delega permisos de lectura a la cuenta de auditoria.

### Configuracion

En `config.yaml` cambiar `mode: "multi"` y agregar la seccion `multi_account`. Ver `config.yaml.example` para el formato completo.

Las credenciales de la cuenta management tambien van por variables de entorno (`HWCLOUD_AK` / `HWCLOUD_SK`).

---

## 10. Sobre Recursos Creados

### Esta herramienta NO crea ningun recurso

El scanner es **100% de solo lectura**. No ejecuta ninguna operacion de Create, Update o Delete.

- **En tu cuenta de Huawei Cloud**: no queda nada
- **En tu maquina local**: se generan reportes en `output/`
- **Logs de auditoria (CTS)**: las llamadas API quedan registradas como operaciones de lectura

### Para eliminar despues del assessment

- **Borrar reportes locales**: eliminar la carpeta `output/`
- **En modo Multi Account**: eliminar las Agencies creadas en IAM > Agencies

---

## 11. Troubleshooting

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
  set HWCLOUD_DOMAIN_ID=tu_domain_id
```

---

## Contacto

Para reportar issues o contribuir: https://github.com/daianape/huawei-cloud-security-scanner/issues
