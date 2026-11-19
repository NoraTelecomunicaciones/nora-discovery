# Nora Discovery

Buscador de equipos de red para Windows, libre y gratuito. Encuentra en segundos los equipos que responden al
protocolo de descubrimiento por UDP 10001: airMAX, airFiber, LTU, airCube, EdgeMAX, UniFi y otros compatibles.

Es un programa nuevo, escrito desde cero por Nora Telecomunicaciones. **No necesita Java ni instalación**: es un
script de Windows PowerShell con ventana propia. No está afiliado a Ubiquiti Inc. ni contiene código suyo.

## Por qué existe

La herramienta clásica de descubrimiento (un `.jar` de 2017) solo funciona con Java 8 y se cierra al abrir en
Java moderno. En vez de depender de un Java antiguo, este proyecto implementa el mismo protocolo de red en un
programa actual que funciona en cualquier Windows 10 u 11 tal como viene.

## Uso

1. Descarga `NoraDiscovery.ps1` y `NoraDiscovery.cmd` en la misma carpeta.
2. Doble clic en `NoraDiscovery.cmd`. Busca automáticamente al abrir.

| Acción | Cómo |
|---|---|
| Buscar de nuevo | Botón **Buscar equipos** o tecla F5 |
| Filtrar | Escribe en **Filtrar** (modelo, nombre, IP, MAC, firmware, ESSID) |
| Ordenar | Clic en el encabezado de la columna (IP y Uptime ordenan por su valor real) |
| Abrir el equipo en el navegador | Doble clic en la fila |
| SSH, copiar IP, MAC o nombre | Clic derecho sobre la fila |
| Guardar la lista | **Exportar CSV** (exporta lo que está visible) |

Al pasar el mouse sobre una fila se muestra el firmware completo y todas las direcciones IP del equipo.

### Modo consola

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File NoraDiscovery.ps1 -Consola
powershell -NoProfile -ExecutionPolicy Bypass -File NoraDiscovery.ps1 -Consola -Segundos 8 | Export-Csv equipos.csv -NoTypeInformation
```

Devuelve objetos con `Modelo, Nombre, IP, MAC, Firmware, ESSID, Modo, Uptime`, listos para filtrar o exportar.

## Cómo funciona

Envía la consulta de descubrimiento (4 bytes) por UDP al puerto 10001, a la difusión de cada red activa del
equipo y al grupo multicast 233.89.188.1, y escucha las respuestas durante 4 segundos. Cada respuesta trae
campos tipo-largo-valor con MAC, direcciones IP, firmware, nombre, modelo, ESSID, modo inalámbrico y tiempo
encendido.

## Requisitos y límites

- Windows 10 u 11 con Windows PowerShell 5.1 (viene incluido) o PowerShell 7.
- El equipo debe estar en la misma red de capa 2 (mismo segmento o VLAN) que los dispositivos: el descubrimiento
  usa difusión y no cruza routers.
- Si el firewall bloquea las respuestas UDP, la lista sale vacía: permite el tráfico de `powershell.exe`.
- Probado en una red de producción con 398 equipos (airCube, LTU, airMAX AC y M, airFiber).

## Licencia

MIT. Úsalo, cópialo y modifícalo libremente.
