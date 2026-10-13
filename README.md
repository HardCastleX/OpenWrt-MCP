# OpenWrt-MCP

MCP local por `stdio` para administrar routers OpenWrt a través de SSH. El servidor corre en tu PC, se conecta únicamente a una IP privada LAN o WireGuard y no abre puertos en el router.

## Requisitos

- Node.js 20 o superior.
- SSH habilitado en OpenWrt y la clave pública del cliente autorizada en el router.
- IP privada LAN o WireGuard enrutable. Para uso remoto, WireGuard debe anunciar la ruta al router y el firewall debe permitir SSH desde el peer VPN.
- Fingerprint SHA256 del host SSH del router, verificado por un canal confiable.

La configuración rechaza direcciones públicas y nombres DNS. Comprueba el host key SSH en cada conexión. La llave privada nunca se incluye en este repositorio.

## Instalación

En la carpeta clonada:

```powershell
npm.cmd install
npm.cmd run build
npm.cmd test
```

Configura estas variables de entorno en Windows antes de iniciar Command Code:

- `OPENWRT_HOST`: IP privada del router, por ejemplo `192.168.1.1` o una IP privada WireGuard.
- `OPENWRT_SSH_PORT`: puerto SSH (opcional, predeterminado `22`).
- `OPENWRT_SSH_USER`: usuario SSH, a menudo `root` en OpenWrt.
- `OPENWRT_SSH_KEY_PATH`: ruta a la clave privada autorizada en OpenWrt.
- `OPENWRT_SSH_KEY_PASSPHRASE`: passphrase de la llave, opcional.
- `OPENWRT_SSH_HOST_FINGERPRINT`: fingerprint pinneado en formato `SHA256:...`.

No desactives la validación de huella. Obtén el fingerprint con `ssh-keygen -lf <host-public-key> -E sha256` después de verificar la clave pública del host por un canal confiable.

## Conectar uno o varios routers a Command Code

Registra una instancia MCP `stdio` de alcance `user` por router. El nombre de servidor y `OPENWRT_MCP_NAME` forman el alias estable visible en Command Code; cada instancia tiene su propia IP, clave y huella, así que el modelo no puede cambiar de router implícitamente durante una operación.

```powershell
cmdc.cmd mcp add --scope user `
  --env OPENWRT_MCP_NAME=openwrt-home `
  --env OPENWRT_HOST=192.168.1.1 `
  --env OPENWRT_SSH_PORT=22 `
  --env OPENWRT_SSH_USER=root `
  --env OPENWRT_SSH_KEY_PATH=C:\Users\TU_USUARIO\.ssh\openwrt-home `
  --env OPENWRT_SSH_HOST_FINGERPRINT=SHA256:HUELLA_HOME `
  openwrt-home -- node C:\Users\TU_USUARIO\OpenWrt-MCP\dist\index.js
```

Añade otro con otro alias y credenciales independientes:

```powershell
cmdc.cmd mcp add --scope user `
  --env OPENWRT_MCP_NAME=openwrt-office `
  --env OPENWRT_HOST=10.8.0.1 `
  --env OPENWRT_SSH_PORT=22 `
  --env OPENWRT_SSH_USER=root `
  --env OPENWRT_SSH_KEY_PATH=C:\Users\TU_USUARIO\.ssh\openwrt-office `
  --env OPENWRT_SSH_HOST_FINGERPRINT=SHA256:HUELLA_OFFICE `
  openwrt-office -- node C:\Users\TU_USUARIO\OpenWrt-MCP\dist\index.js
```

Usa IP privada LAN/WireGuard para cada destino; no clones una configuración cambiando solo la etiqueta. Comprueba con `cmdc.cmd mcp list` y `/mcp`. No guardes claves privadas o passphrases en el repositorio.

## Herramientas

- `get_router_status(section)`: lectura predefinida para `system`, `storage`, `interfaces`, `wireless`, `clients` o `logs`.
- `get_device_capabilities()`: lectura de versión/target OpenWrt, gestores detectados (`apk`/`opkg`), herramientas disponibles, nombres de interfaces, rutas y cambios UCI pendientes. El hash de configuración se calcula en el router; el MCP no recibe las claves privadas existentes.
- `plan_wireguard_tunnel(...)`: valida y previsualiza la creación de una interfaz WireGuard nueva. Genera una clave local para el túnel y devuelve su clave pública, resumen y digest de aprobación; la clave privada permanece solo en memoria del proceso MCP y nunca aparece en la respuesta. No cambia el router.
- `apply_wireguard_tunnel(planId, digest)`: aplica únicamente el plan previo, mientras el mismo proceso MCP siga vivo y el digest/configuración no haya cambiado. Requiere aprobación del cliente MCP. No toca interfaces existentes, firewall, WAN/LAN ni rutas por defecto; detecta gestor de paquetes, pero no instala ni actualiza paquetes.
- `verify_wireguard_tunnel(interfaceName)`: verifica en una conexión SSH nueva si está configurado/activo y si hay handshake reciente. “Arriba sin handshake” no significa que el peer remoto sea alcanzable.
- `execute_command(command, confirm)`: herramienta avanzada de shell SSH. La repetición literal de `confirm` **no es una aprobación humana ni una sandbox**; puede cambiar la configuración o interrumpir el acceso.

### Flujo WireGuard conversacional

Pide primero `get_device_capabilities`, luego describe el túnel y solicita `plan_wireguard_tunnel`. Revisa direcciones, AllowedIPs, endpoint y clave pública en la respuesta. Para crear el túnel, pide explícitamente `apply_wireguard_tunnel` con el `planId` y digest del plan aprobado; termina con `verify_wireguard_tunnel` desde una conexión nueva. No se crea ni aplica ningún túnel al iniciar el MCP.

El túnel está aislado deliberadamente: `0.0.0.0/0` y `::/0`, AllowedIPs que se solapen con rutas existentes, nombres ya utilizados y cambios UCI pendientes son rechazados. Tampoco se modifica el firewall, así que este primer corte crea la interfaz/peer local pero no garantiza conectividad entrante a través de zonas WAN; la exposición de endpoint debe configurarse por separado con una operación específica y revisada.

No hay rollback general ni garantía de recuperación si el sistema queda inaccesible. La previsualización, comprobación de hash y verificación independiente reducen errores, pero no pueden demostrar que el peer remoto funcionará. Si se pierde la ruta SSH, la recuperación puede requerir acceso LAN/local. No ejecutes sesiones con `--yolo`; las herramientas mutables deben tener aprobación en el cliente MCP. Timeout por llamada: 30 segundos; salida combinada máxima: 32 KiB.

La clave privada temporal del plan vive en memoria del MCP durante un máximo de 10 minutos. Si se reinicia el servidor entre `plan` y `apply`, crea un plan nuevo y distribuye la nueva clave pública al peer remoto.

## Estado experimental y pendientes de la beta

La configuración WireGuard es experimental. Se han probado detección de capacidades, validación, generación de claves, la previsualización local y el parser de shell; `apply_wireguard_tunnel` **todavía no se ha validado creando una interfaz en un router de laboratorio**. No lo uses en el único router que te da acceso remoto hasta completar esa prueba.

Un plan con `peers: []` sirve solo para validar la creación de una interfaz local aislada; no establece handshake. Para verificar conectividad real hace falta un peer remoto configurado con la clave pública generada. Pendiente antes de una versión estable: probar aplicación/activación y retirada en un OpenWrt de laboratorio, verificar el formato real de cambios UCI y completar una conexión con handshake remoto, además de rotar la clave `wg0` que se expuso accidentalmente durante el diagnóstico previo.

## Desarrollo y pruebas

```powershell
npm.cmd run typecheck
npm.cmd test
npm.cmd run build
```

Los tests cubren validación de IP privada, confirmación de comandos y pinning de fingerprint. La conexión manual al router requiere configurar las variables anteriores.
