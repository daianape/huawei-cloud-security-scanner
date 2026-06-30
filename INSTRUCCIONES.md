# Instrucciones - Huawei Cloud Security Scanner

Guia completa paso a paso para configurar y ejecutar el scanner de seguridad en cuentas de Huawei Cloud.

---

## Tabla de Contenidos

1. [Requisitos Previos](#1-requisitos-previos)
2. [Instalacion](#2-instalacion)
3. [Configuracion Single Account](#3-configuracion-single-account)
4. [Configuracion Multi Account](#4-configuracion-multi-account)
5. [Ejecucion del Scanner](#5-ejecucion-del-scanner)
6. [Visualizacion de Reportes](#6-visualizacion-de-reportes)
7. [Exportacion de Informes](#7-exportacion-de-informes)
8. [Sobre Recursos Creados](#8-sobre-recursos-creados)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Requisitos Previos

- Python 3.9 o superior
- Cuenta de Huawei Cloud con acceso a la consola
- Access Key (AK) y Secret Key (SK) con permisos de lectura
- Conectividad a internet (para acceder a las APIs de Huawei Cloud)

### Permisos minimos requeridos

El usuario o agency necesita los siguientes permisos de **solo lectura**:

| Servicio | Rol/Politica |
|----------|-------------|
| IAM | Security Administrator (ReadOnly) |
| VPC | VPC ReadOnlyAccess |
| ECS | ECS ReadOnlyAccess |
| OBS | OBS ReadOnlyAccess |
| CTS | CTS ReadOnlyAccess |
| ELB | ELB ReadOnlyAccess |

> **Recomendacion**: crear un usuario IAM dedicado para auditorias con solo permisos de lectura.

### Como crear el usuario IAM para el scanner

**Paso 1: Crear un grupo de usuarios**

1. Ingresa a la consola de Huawei Cloud > **IAM** > **User Groups**
2. Click en **Create User Group**
3. Nombre: `security-auditors`
4. Click en **OK**

**Paso 2: Asignar permisos al grupo**

1. En la lista de grupos, click en `security-auditors`
2. Tab **Permissions** > **Authorize**
3. Buscar y seleccionar los siguientes roles/politicas del sistema:
   - `Security Administrator` (este incluye lectura de IAM, password policy, MFA, etc.)
   - `VPC ReadOnlyAccess`
   - `ECS ReadOnlyAccess`
   - `OBS ReadOnlyAccess` (o `Tenant Guest` si no existe el especifico)
   - `CTS ReadOnlyAccess`
   - `ELB ReadOnlyAccess`
4. Seleccionar el **Scope**: `All resources` (para que aplique en todas las regiones)
5. Click en **OK**

> Nota: si no encontras un rol "ReadOnlyAccess" especifico, podes usar `Tenant Guest` que otorga lectura global a todos los servicios. Es mas amplio pero funcional.

**Paso 3: Crear el usuario IAM**

1. Ve a **IAM** > **Users** > **Create User**
2. Configurar:
   - **Username**: `security-scanner`
   - **Access Type**: marcar **Programmatic access** (genera AK/SK)
   - **Console access**: desmarcar (no necesita acceso a consola)
3. Click en **Next**
4. Asignar al grupo `security-auditors`
5. Click en **Create**
6. **Descargar las credenciales** (AK/SK) - solo se muestran una vez

**Paso 4: Usar las credenciales en el scanner**

Copiar el Access Key (AK) y Secret Key (SK) descargados al `config/config.yaml` o configurarlos como variables de entorno.

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

### (Opcional) Instalar SDK de OBS

Para escanear buckets de OBS, instalar el SDK adicional:

```bash
pip install esdk-obs-python
```

---

## 3. Configuracion Single Account

Usa este modo cuando quieras escanear **una sola cuenta** de Huawei Cloud.

### Opcion A: Modo interactivo (recomendado)

La forma mas segura. Las credenciales se ingresan por prompt y solo existen en memoria durante la ejecucion:

```bash
python main.py scan --interactive
```

Te va a pedir:
```
  Access Key (AK): XXXXXXXXXXXXXXXXXX
  Secret Key (SK): (oculto, no se muestra en pantalla)
  Project ID: abc123def456...
  Region [la-south-2]: la-south-2
```

Las credenciales **no quedan guardadas en ningun archivo**. Al terminar la ejecucion, desaparecen.

### Opcion B: Variables de entorno

Util para automatizacion sin archivos en disco:

```bash
# Windows
set HWCLOUD_AK=tu_access_key
set HWCLOUD_SK=tu_secret_key
set HWCLOUD_PROJECT_ID=tu_project_id
set HWCLOUD_REGION=la-south-2

# Linux/Mac
export HWCLOUD_AK=tu_access_key
export HWCLOUD_SK=tu_secret_key
export HWCLOUD_PROJECT_ID=tu_project_id
export HWCLOUD_REGION=la-south-2

# Luego ejecutar normalmente
python main.py scan
```

### Opcion C: Archivo config.yaml

Para ejecuciones repetidas o automatizadas. **Proteger el archivo con permisos adecuados.**

#### Paso 1: Obtener credenciales

1. Ingresa a la consola de Huawei Cloud: https://console.huaweicloud.com
2. Click en tu nombre de usuario (esquina superior derecha) > **My Credentials**
3. Ve a la seccion **Access Keys**
4. Click en **Create Access Key**
5. Guarda el AK y SK que se descargan

### Paso 2: Obtener Project ID

1. En la consola, click en tu nombre de usuario > **My Credentials**
2. En la seccion **API Credentials** vas a ver el **Project ID** de tu region
3. Copiar el Project ID correspondiente a la region que quieras escanear

### Paso 3: Crear archivo de configuracion

```bash
copy config\config.yaml.example config\config.yaml
```

Editar `config/config.yaml`:

```yaml
# Modo single account
mode: "single"

# Region a escanear (ejemplos: la-south-2, ap-southeast-1, cn-north-4)
region: "la-south-2"

# Project ID de la region
project_id: "abc123def456..."

# Credenciales
credentials:
  access_key: "TU_ACCESS_KEY"
  secret_key: "TU_SECRET_KEY"

# Scanners a ejecutar (true/false)
scanners:
  iam: true
  vpc: true
  ecs: true
  obs: true
  cts: true
  elb: true

# Output
output:
  directory: "./output"
  formats:
    - html
    - json
```

### Configuracion Multi Region (opcional)

Para escanear multiples regiones en una sola ejecucion, agregar la seccion `regions` al config:

```yaml
# Escanear multiples regiones (cada una con su project_id)
regions:
  - region: "la-south-2"
    project_id: "project-id-region-1"
  - region: "ap-southeast-1"
    project_id: "project-id-region-2"
  - region: "cn-north-4"
    project_id: "project-id-region-3"
```

> **Nota:** Cada region tiene su propio Project ID. Lo podes obtener desde My Credentials > API Credentials en la consola, seleccionando la region correspondiente.

Si no configuras la seccion `regions`, el scanner usa la region unica definida en `region:`.

---

## 4. Configuracion Multi Account

Usa este modo cuando necesites escanear **multiples cuentas** de Huawei Cloud desde una cuenta central de auditoria.

### Concepto: IAM Agencies

Huawei Cloud usa **Agencies** para delegar acceso entre cuentas (equivalente a AWS AssumeRole). El flujo es:

```
Cuenta de Auditoria (Management)
         │
         │ Assume Agency
         ▼
┌─────────────────┐
│ Cuenta Target A │  ← Agency creada que confia en la cuenta management
│ Cuenta Target B │
│ Cuenta Target C │
└─────────────────┘
```

### Paso 1: Crear Agency en cada cuenta target

En **cada cuenta que quieras escanear**, crear una Agency:

1. Ingresa a la consola de la cuenta target
2. Ve a **IAM > Agencies**
3. Click en **Create Agency**
4. Configurar:
   - **Agency Name**: `security-scanner-agency`
   - **Agency Type**: Account
   - **Delegating Account**: ingresar el **Domain ID** de tu cuenta de auditoria
   - **Validity Period**: Unlimited (o definir un periodo)
   - **Permissions**: asignar los roles de solo lectura listados en requisitos
5. Click en **OK**

### Paso 2: Obtener datos de cada cuenta target

Para cada cuenta target, anotar:
- **Domain ID**: My Credentials > Account ID (Domain ID)
- **Project ID**: My Credentials > API Credentials > Project ID (de la region a escanear)
- **Agency Name**: el nombre que le diste (ej: `security-scanner-agency`)

### Paso 3: Obtener datos de la cuenta management

De tu cuenta de auditoria (desde donde corres el scanner):
- **Access Key y Secret Key** (con permisos para asumir agencies)
- **Domain ID**: My Credentials > Account ID

### Paso 4: Configurar config.yaml

```yaml
mode: "multi"

# Region por defecto
region: "la-south-2"

# Cuenta management (desde donde se ejecuta el scanner)
multi_account:
  management_account:
    access_key: "MANAGEMENT_AK"
    secret_key: "MANAGEMENT_SK"
    domain_id: "management-domain-id-xxxx"

  # Cuentas a escanear
  target_accounts:
    - account_name: "Produccion"
      domain_id: "target-domain-id-prod"
      agency_name: "security-scanner-agency"
      project_id: "target-project-id-prod"
      region: "la-south-2"

    - account_name: "Desarrollo"
      domain_id: "target-domain-id-dev"
      agency_name: "security-scanner-agency"
      project_id: "target-project-id-dev"
      region: "la-south-2"

    - account_name: "Staging"
      domain_id: "target-domain-id-stg"
      agency_name: "security-scanner-agency"
      project_id: "target-project-id-stg"
      region: "ap-southeast-1"

# Scanners
scanners:
  iam: true
  vpc: true
  ecs: true
  obs: true
  cts: true
  elb: true

# Output
output:
  directory: "./output"
  formats:
    - html
    - json
    - csv
```

---

## 5. Ejecucion del Scanner

### Comando basico

```bash
python main.py scan
```

### Opciones disponibles

```bash
# Especificar archivo de configuracion
python main.py scan --config config/config.yaml

# Elegir directorio de output
python main.py scan --output ./mis-reportes

# Elegir formatos de reporte
python main.py scan --format html,json,csv

# Ejecutar solo scanners especificos
python main.py scan --scanners iam,vpc

# === OPCIONES DE REGION ===

# Escanear una region especifica (override config)
python main.py scan --regions la-south-2

# Escanear multiples regiones
python main.py scan --regions la-south-2,ap-southeast-1,cn-north-4

# Escanear TODAS las regiones disponibles
python main.py scan --regions all

# Modo verbose (mas detalle en logs)
python main.py scan --verbose
```

### Otros comandos

```bash
# Validar configuracion sin ejecutar el scan
python main.py validate

# Listar scanners disponibles
python main.py list-scanners

# Listar todas las regiones disponibles
python main.py list-regions

# Ver version
python main.py --version
```

### Ejemplo de salida

```
╭─────────────────────────────────────────╮
│   Huawei Cloud Security Scanner         │
│   Security Assessment Tool v1.0.0       │
╰─────────────────────────────────────────╯

✓ Configuration loaded successfully
✓ Authenticated (single mode) - 1 account(s) to scan
✓ Scanners: IAM, VPC, ECS, OBS, CTS, ELB

Scanning account: single-account (region: la-south-2)
  IAM: 15 checks, 4 failed
  VPC: 8 checks, 2 failed
  ECS: 5 checks, 1 failed
  OBS: 6 checks, 2 failed
  CTS: 3 checks, 0 failed
  ELB: 4 checks, 1 failed

┌─────────── Scan Results Summary ───────────┐
│ Account    │ Region    │ Total │ Pass │ Fail │
│ single-acc │ la-south-2│   41  │  31  │  10  │
└────────────────────────────────────────────┘

✓ HTML Dashboard: ./output/index.html
✓ JSON Report: ./output/scan_report_20260630_160000.json

Scan complete!
Open ./output/index.html in your browser to view the dashboard.
```

---

## 6. Visualizacion de Reportes

### Dashboard HTML

Despues de ejecutar el scan, abrir el archivo HTML generado:

```bash
# Windows - abrir directamente en el browser
start output\index.html

# Linux
xdg-open output/index.html

# Mac
open output/index.html
```

El dashboard incluye:

- **Pagina Home**: resumen de severidades con barras de progreso, cards por servicio con contadores, graficos de torta y barras
- **Pagina Findings**: tabla completa de todos los hallazgos con filtros por severidad, status y servicio
- **Paginas por Servicio**: hallazgos detallados filtrados por cada servicio (IAM, VPC, etc.)
- **Selector de cuentas**: dropdown para filtrar por cuenta (en modo multi-account)

### Navegacion del Dashboard

- **Sidebar izquierda**: navegacion entre Home, Findings y cada servicio escaneado
- **Filtros**: dropdowns para severidad (Critical/High/Medium/Low), status (Pass/Fail) y servicio
- **Selector de cuenta**: arriba a la derecha, para filtrar hallazgos por cuenta especifica

---

## 7. Exportacion de Informes

### Formatos disponibles

| Formato | Archivo generado | Uso |
|---------|-----------------|-----|
| HTML | `output/index.html` | Dashboard visual para presentaciones |
| JSON | `output/scan_report_FECHA.json` | Integracion con otras herramientas, SIEM |
| JSON Summary | `output/scan_summary_FECHA.json` | Resumen rapido sin detalle |
| CSV | `output/scan_findings_FECHA.csv` | Abrir en Excel para analisis/filtrado |

### Generar todos los formatos

```bash
python main.py scan --format html,json,csv
```

### Uso del CSV en Excel

El archivo CSV se genera con encoding UTF-8 BOM, compatible con Excel sin necesidad de importacion especial. Columnas incluidas:

- account_name, account_id, region
- service, category, check_id, check_title
- severity, status
- description, resource_id, resource_name
- remediation, reference_url
- timestamp

### Uso del JSON para automatizacion

El JSON completo tiene la estructura:

```json
{
  "scanner": "Huawei Cloud Security Scanner",
  "version": "1.0.0",
  "generated_at": "2026-06-30T16:00:00",
  "results": [
    {
      "summary": { ... },
      "findings": [ ... ]
    }
  ]
}
```

Puede ser consumido por scripts de automatizacion, enviado a un SIEM o usado para generar tickets automaticos.

---

## 8. Sobre Recursos Creados

### Esta herramienta NO crea ningun recurso

El scanner es **100% de solo lectura (read-only)**. Todas las llamadas a las APIs de Huawei Cloud son operaciones de tipo:

- `List*` (listar recursos)
- `Show*` (obtener detalle de un recurso)
- `Get*` (obtener configuracion)

**No ejecuta ninguna operacion de:**
- Create (crear)
- Update (modificar)
- Delete (eliminar)
- Put (sobreescribir)

### Que pasa despues de ejecutar el scanner?

- **En tu cuenta de Huawei Cloud**: no queda nada. No se crean usuarios, roles, instancias ni ningun otro recurso.
- **En tu maquina local**: se generan los archivos de reporte en la carpeta `output/`. Si queres limpiar, simplemente borra esa carpeta.
- **Logs de auditoria (CTS)**: las llamadas API del scanner quedaran registradas en Cloud Trace Service como operaciones de lectura. Esto es normal y esperado.

### Unico recurso requerido (Multi Account): IAM Agency

En el modo **Multi Account**, necesitas crear manualmente una **Agency** en cada cuenta target ANTES de ejecutar el scanner. Esta Agency es un recurso de IAM que otorga permisos delegados.

**Para eliminar la Agency despues del assessment:**

1. Ingresa a la consola de la cuenta target
2. Ve a **IAM > Agencies**
3. Busca la agency `security-scanner-agency`
4. Click en **Delete**
5. Confirmar la eliminacion

Esto revoca inmediatamente los permisos delegados. No es necesario eliminar nada mas.

---

## 9. Troubleshooting

### Error: "Configuration file not found"

```
Solucion: Copiar config.yaml.example a config.yaml
  copy config\config.yaml.example config\config.yaml
```

### Error: "Missing credentials"

```
Solucion: Verificar que access_key y secret_key esten configurados
en config.yaml o como variables de entorno (HWCLOUD_AK, HWCLOUD_SK)
```

### Error: "Failed to validate credentials"

```
Posibles causas:
- AK/SK incorrectos
- El usuario fue deshabilitado
- La region configurada no es valida
- Sin conectividad a internet

Solucion: Verificar credenciales en la consola de Huawei Cloud
```

### Error: "Failed to assume agency"

```
Posibles causas (Multi Account):
- La Agency no existe en la cuenta target
- El domain_id de la cuenta management no coincide con el trustee
- La Agency no tiene los permisos necesarios
- El agency_name en config.yaml no coincide con el nombre real

Solucion: Verificar la configuracion de la Agency en IAM > Agencies
de la cuenta target
```

### Error: "OBS SDK not available"

```
Solucion: Instalar el SDK de OBS
  pip install esdk-obs-python
```

### El dashboard no muestra graficos

```
Solucion: El dashboard usa Chart.js desde CDN. Necesitas conexion
a internet al abrir el HTML, o el browser debe permitir cargar
scripts externos.
```

### Regiones disponibles

Ejecutar `python main.py list-regions` para ver la lista completa. Algunas de las mas comunes:

| Region | Codigo |
|--------|--------|
| Latin America - Santiago | la-south-2 |
| Latin America - Mexico City | la-north-2 |
| South America - Sao Paulo | sa-brazil-1 |
| Asia Pacific - Singapore | ap-southeast-3 |
| Asia Pacific - Hong Kong | ap-southeast-1 |
| Asia Pacific - Jakarta | ap-southeast-4 |
| Europe - Paris | eu-west-0 |
| Europe - Dublin | eu-west-101 |
| Africa - Johannesburg | af-south-1 |
| China North - Beijing | cn-north-4 |
| China East - Shanghai | cn-east-3 |
| Middle East - Istanbul | tr-west-1 |

> **Nota sobre multi-region:** Cada region tiene su propio Project ID. Cuando ejecutas `--regions all`, el scanner intenta conectar a cada region. Si no tenes Project ID para una region, puede fallar en esa region y continuar con las demas.

Consultar la lista completa en: https://developer.huaweicloud.com/endpoint

---

## Contacto

Para reportar issues o contribuir: https://github.com/daianape/huawei-cloud-security-scanner/issues
