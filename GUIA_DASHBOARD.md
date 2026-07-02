# Guia de Uso del Dashboard HTML

Esta guia explica como navegar y aprovechar el dashboard HTML interactivo generado por Huawei Cloud Security Scanner.

![Vista general del dashboard](docs/images/dashboard-home-full.png)

---

## Como Abrir el Dashboard

Despues de ejecutar el scan, el reporte se genera en:

```
output/index.html
```

Abrilo directamente en tu navegador (doble click o arrastrar al browser). No necesita servidor web, funciona como archivo local.

---

## Estructura General

El dashboard tiene 3 zonas principales:

```
+------------------+--------------------------------------------+
|                  |  TOP BAR (breadcrumb, filtro de cuenta)     |
|    SIDEBAR       +--------------------------------------------+
|  (navegacion)    |                                            |
|                  |            CONTENIDO PRINCIPAL              |
|                  |         (cambia segun la pagina)            |
|                  |                                            |
+------------------+--------------------------------------------+
```

---

## 1. Sidebar (Panel Izquierdo)

El sidebar oscuro a la izquierda contiene la navegacion principal.

![Sidebar con navegacion de servicios](docs/images/dashboard-sidebar.png)

### Secciones del Sidebar

| Item | Que hace |
|------|----------|
| **Home** | Ir a la pagina principal con KPIs y resumen ejecutivo |
| **FINDINGS** | Ir a la tabla completa de todos los hallazgos |
| **Servicios** (lista dinamica) | Ir al detalle de un servicio especifico (IAM, VPC, ECS, etc.) |

### Como usarlo

- Click en cualquier item para navegar a esa pagina
- El item activo se resalta en azul
- En mobile/tablet: el sidebar se oculta; usar el boton hamburguesa (tres lineas) arriba a la izquierda para mostrarlo

---

## 2. Top Bar (Barra Superior)

La barra superior se mantiene fija al hacer scroll.

| Elemento | Funcion |
|----------|---------|
| Breadcrumb | Muestra la pagina actual (ej: "Home / IAM") |
| Account filter | Dropdown para filtrar findings por cuenta (util en multi-account) |
| Menu toggle | Solo en mobile: abre/cierra el sidebar |

---

## 3. Pagina Home (INDEX)

Es la vista ejecutiva. Muestra el resumen del scan completo.

![Pagina Home con KPIs y graficos](docs/images/dashboard-home-kpis.png)

### 3.1 Stat Cards (KPIs)

Las tarjetas de colores en la parte superior muestran metricas clave:

| Card | Que muestra | Color |
|------|-------------|-------|
| Services Scanned | Cantidad de servicios analizados | Verde |
| Total Checks | Total de checks ejecutados (pass + fail) | Azul |
| Failed Findings | Cantidad de hallazgos fallidos | Rojo |
| Passed | Checks que pasaron correctamente | Teal |
| Critical+High | Suma de hallazgos criticos y altos | Navy |
| Errors | Checks que dieron error (API no respondio, etc.) | Amarillo |

### 3.2 Summary (Resumen de Severidad)

Click en "Summary" para expandir. Muestra barras de progreso con el porcentaje de cada severidad:

- **Critical** (violeta) - Problemas que requieren accion inmediata
- **High** (rojo) - Problemas de alta prioridad
- **Medium** (amarillo) - Riesgo moderado, planificar remediacion
- **Low** (cyan) - Riesgo bajo, mejoras sugeridas
- **Info** (verde) - Solo informativo

### 3.3 Graficos

Dos graficos lado a lado:

![Graficos de severidad y servicios](docs/images/dashboard-home-charts.png)

| Grafico | Tipo | Que muestra |
|---------|------|-------------|
| High Risk - Group by Service | Barras | Cantidad de findings fallidos por servicio |
| High Risk - Group by Severity | Doughnut | Distribucion de severidades (solo findings fallidos) |

Los graficos son interactivos: pasar el mouse sobre un segmento muestra el valor exacto.

### 3.4 Services Overview

Grid de cards clickeables, una por cada servicio escaneado. Cada card muestra:
- Nombre del servicio
- Badge "Security"
- Numero de findings

**Click en una card** para ir a la pagina Findings con ese servicio ya filtrado.

### 3.5 Regions Overview

Grid de cards clickeables, una por cada region escaneada. Cada card muestra:
- Nombre de la region (ej: LA-SOUTH-2, SA-ARGENTINA-1)
- Total de findings en esa region
- Indicador de severidad (rojo si hay Critical/High, amarillo si Medium, cyan si solo Low)

**Click en una card** para ir a la pagina Findings con esa region ya filtrada.

---

## 4. Pagina Findings (Tabla de Hallazgos)

Esta pagina muestra TODOS los hallazgos en una tabla unificada.

![Tabla de findings con filtros](docs/images/dashboard-findings-table.png)

### 4.1 Filtros

Arriba de la tabla hay 4 filtros combinables:

| Filtro | Opciones |
|--------|----------|
| **Service** | Dropdown con todos los servicios escaneados |
| **Region** | Dropdown con todas las regiones detectadas |
| **Severity** | Critical / High / Medium / Low |
| **Status** | Fail / Pass |

Los filtros se combinan (AND): si seleccionas Service=IAM + Region=la-south-2 + Severity=High, veras solo findings de IAM en la-south-2 con severidad High.

### 4.2 Busqueda

El campo "Search" arriba a la derecha filtra en tiempo real por:
- Nombre del servicio
- Check ID
- Descripcion
- Resource ID

Escribi cualquier texto y la tabla se actualiza al instante.

### 4.3 Ordenamiento

Click en el header de cualquier columna para ordenar:
- Primer click: ascendente (A-Z)
- Segundo click: descendente (Z-A)

Las columnas ordenables son: Service, Region, Check, Type, ResourceID, Severity, Status.

### 4.4 Columnas de la Tabla

| Columna | Que muestra |
|---------|-------------|
| Service | Nombre del servicio (IAM, VPC, RDS...) |
| Region | Region donde se encontro (ej: la-south-2) |
| Check | ID del check (ej: IAM-01, VPC-03) |
| Type | Tipo de hallazgo (Security) |
| ResourceID | Nombre o ID del recurso afectado |
| Severity | Badge de color con la severidad |
| Status | Badge de estado |

### 4.5 Exportar

| Boton | Que hace |
|-------|----------|
| **Copy** | Copia la tabla al clipboard (para pegar en Excel) |
| **CSV** | Descarga un archivo CSV con los findings filtrados |

### 4.6 Tabs

| Tab | Contenido |
|-----|-----------|
| Findings | Tabla principal de hallazgos activos |
| Suppressed | Hallazgos suprimidos (futuro) |

---

## 5. Pagina de Detalle por Servicio

Se accede haciendo click en un servicio (desde el sidebar o desde las Service Cards en Home).

![Vista detalle de un servicio con resource cards](docs/images/dashboard-service-detail.png)

### 5.1 Stat Cards del Servicio

Similares a Home pero especificas del servicio:
- **Resources**: Cantidad de recursos evaluados
- **Total Findings**: Hallazgos fallidos en este servicio
- **Rules Executed**: Checks ejecutados
- **Unique Rules**: Checks distintos aplicados
- **Suppressed**: Hallazgos suprimidos

### 5.2 Filtros del Servicio

- **Checks**: Dropdown para filtrar por check especifico (ej: solo IAM-01)
- **Pillar**: Filtro por pilar (Security, Reliability, etc.)
- **Criticality**: Filtro por severidad

### 5.3 Check Cards

Grid de cards mostrando cada check unico del servicio:
- Nombre del check (ej: IAM-01)
- Badge de pilar
- Indicador de severidad con color

### 5.4 Detail (Vista de Recursos)

La seccion "Detail" muestra los recursos individuales agrupados por region:

```
la-south-2
  +-----------------------------------------------+
  | 1. nombre-del-recurso            [SERVICIO]   |
  +-----------------------------------------------+
  | Check        | Current Value  | Recommendation |
  | X IAM-01     | MFA disabled   | Enable MFA...  |
  | V IAM-02     | Key rotated    | -              |
  +-----------------------------------------------+

  +-----------------------------------------------+
  | 2. otro-recurso                  [SERVICIO]   |
  +-----------------------------------------------+
  | ...                                           |
  +-----------------------------------------------+
```

Cada resource card tiene:
- **Header dorado** con el nombre/ID del recurso y badge del servicio
- **Tabla interna** con los checks aplicados a ese recurso
- **Iconos de estado**: V verde (pass), X rojo (fail), ! amarillo (warning)
- **Current Value**: Lo que se encontro (el problema)
- **Recommendation**: Que hacer para remediarlo

---

## 6. Filtro Rapido (Click en Cards)

Muchos elementos del dashboard son clickeables y navegan directamente a Findings con un filtro pre-aplicado:

| Elemento clickeable | Que filtra |
|---------------------|------------|
| **Service card** (Home > Services Overview) | Findings de ese servicio |
| **Region card** (Home > Regions Overview) | Findings de esa region |
| **Barra de severidad** (Home > Summary) | Findings de esa severidad |
| **Card "Failed Findings"** (stat card roja) | Findings con status = Fail |
| **Card "Passed"** (stat card teal) | Findings con status = Pass |
| **Card "Critical+High"** (stat card navy) | Findings con severidad Critical o High |

### Como funciona

1. Click en cualquiera de estos elementos
2. El dashboard navega automaticamente a la pagina Findings
3. El filtro correspondiente se aplica automaticamente
4. La tabla muestra solo los resultados filtrados

Para volver a ver todo: cambiar los filtros a "All" o hacer click en "Home" en el sidebar.

---

## 7. Secciones Colapsables

Los paneles con header dorado o teal son colapsables:

- **Click en el header** para expandir/colapsar
- El icono cambia: `+` (colapsado) / `-` (expandido)
- Por defecto, "Summary" esta colapsado y los demas expandidos

---

## 8. Responsive (Mobile/Tablet)

En pantallas chicas (< 900px):

![Vista mobile con sidebar colapsado](docs/images/dashboard-mobile.png)

- El sidebar se oculta automaticamente
- Aparece un boton hamburguesa en la top bar
- Las stat cards se reorganizan en 2 columnas
- Los graficos se apilan verticalmente
- Las check cards se muestran en 1 columna

---

## 9. Interpretacion de Resultados

### Priorizar la remediacion

1. **Empezar por Critical+High** en la pagina Home (card navy)
2. Ir a Findings, filtrar por Severity = Critical
3. Para cada servicio con findings criticos, entrar al detalle
4. En la vista de recursos, leer la columna "Recommendation"

### Flujo recomendado de revision

```
Home (vision ejecutiva)
  |
  v
Findings (filtrar por Critical)
  |
  v
Servicio con mas findings (click en card)
  |
  v
Detail -> ver recurso por recurso -> remediar
  |
  v
Repetir para High, luego Medium
```

### Que significan los KPIs

| Si ves... | Significa... |
|-----------|--------------|
| Failed Findings = 0 | Excelente! No se encontraron problemas |
| Critical+High > 0 | Hay problemas urgentes que atender |
| Errors > 0 | Algunos checks no pudieron ejecutarse (revisar permisos o disponibilidad del servicio) |
| Total Checks alto, Failed bajo | Buena postura de seguridad general |

---

## 9. Exportar para Reportes

### Opcion 1: CSV desde el Dashboard

1. Ir a Findings
2. Aplicar filtros si necesitas un subconjunto
3. Click en "CSV" - se descarga `findings.csv`
4. Abrir en Excel para analisis adicional

### Opcion 2: Copiar tabla

1. Ir a Findings
2. Click en "Copy"
3. Pegar en Excel, Google Sheets, o un mail

### Opcion 3: Imprimir / PDF

1. En el navegador: Ctrl+P
2. Seleccionar "Guardar como PDF"
3. Recomendacion: estar en la pagina que quieras imprimir

---

## 10. Tips y Trucos

| Tip | Descripcion |
|-----|-------------|
| Busqueda rapida | En Findings, escribir el nombre del recurso en Search |
| Comparar regiones | Filtrar por servicio, luego mirar la columna Region |
| Foco en un check | En la vista de servicio, usar el filtro Checks para aislar un check |
| Multi-account | Usar el dropdown de Account en la top bar para ver una cuenta a la vez |
| Compartir reporte | El HTML es un solo archivo - se puede enviar por mail o Slack |
| Offline | Funciona sin internet (Chart.js se carga desde CDN, pero los datos son locales) |

---

## 11. Limitaciones Conocidas

- El archivo HTML puede ser grande si hay muchos findings (> 5000 recursos)
- Chart.js se carga desde CDN; sin internet los graficos no se renderizan (los datos y tablas si funcionan)
- El tab "Suppressed" es placeholder para futuras versiones
- El filtro de servicio en la vista detalle (applyServiceFilter) es placeholder

---

## 12. Troubleshooting del Dashboard

| Problema | Solucion |
|----------|----------|
| Graficos no aparecen | Verificar conexion a internet (Chart.js CDN) |
| HTML en blanco | Verificar que el scan haya generado findings (revisar output/data/) |
| Tabla vacia | Verificar filtros activos; resetear seleccionando "All" en cada filtro |
| Sidebar no aparece (mobile) | Click en el icono de tres lineas arriba a la izquierda |
| CSV con caracteres raros | Abrir con encoding UTF-8 en Excel (Datos > Desde texto) |

---

## Imagenes del Dashboard

Las imagenes de esta guia se encuentran en `docs/images/`. Para generarlas:

1. Ejecutar un scan: `python main.py scan --no-verify-ssl`
2. Abrir `output/index.html` en el navegador
3. Tomar los siguientes screenshots y guardarlos con estos nombres exactos:

| Archivo | Que capturar |
|---------|--------------|
| `dashboard-home-full.png` | Pagina Home completa (vista general con sidebar visible) |
| `dashboard-sidebar.png` | Solo el sidebar (recortar la zona izquierda) |
| `dashboard-home-kpis.png` | Stat cards + barras de severidad (zona superior de Home) |
| `dashboard-home-charts.png` | Los dos graficos (doughnut + barras) |
| `dashboard-findings-table.png` | Pagina Findings con la tabla y filtros visibles |
| `dashboard-service-detail.png` | Vista detalle de un servicio (ej: IAM) con resource cards |
| `dashboard-mobile.png` | Vista mobile (F12 > toggle device toolbar > 375px ancho) |

**Tip**: En Chrome, F12 > "Toggle device toolbar" para simular mobile.
