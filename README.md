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

## Conectar a Command Code

Registra un servidor MCP `stdio` de alcance de usuario. Reemplaza la IP, clave y ruta por tus valores:

```powershell
cmd mcp add --scope user --env OPENWRT_HOST=192.168.1.1 --env OPENWRT_SSH_PORT=22 --env OPENWRT_SSH_USER=root --env OPENWRT_SSH_KEY_PATH=C:\Users\TU_USUARIO\.ssh\openwrt_ed25519 --env OPENWRT_SSH_HOST_FINGERPRINT=SHA256:HUELLA_VERIFICADA openwrt -- node C:\Users\TU_USUARIO\Desktop\OpenMCP\OpenWrt-MCP\dist\index.js
```

Verifica la conexión con `cmd mcp list` o `/mcp` dentro de Command Code. Evita guardar la passphrase en el comando o en archivos versionados.

## Herramientas

- `get_router_status(section)`: lectura predefinida para `system`, `storage`, `interfaces`, `wireless`, `clients` o `logs`.
- `execute_command(command, confirm)`: ejecuta el comando SSH literal solo cuando `confirm` coincide exactamente con `command`; de otro modo no abre SSH. Puede cambiar la configuración o interrumpir el acceso al router. No incluyas secretos si no quieres que aparezcan en el historial.

El servidor marca la herramienta como potencialmente destructiva y requiere la repetición literal del comando como barrera adicional. Command Code puede además pedir aprobación MCP dependiendo de la configuración de permisos. No ejecutes sesiones con `--yolo`. Timeout por llamada: 30 segundos; salida combinada máxima: 32 KiB.

## Desarrollo y pruebas

```powershell
npm.cmd run typecheck
npm.cmd test
npm.cmd run build
```

Los tests cubren validación de IP privada, confirmación de comandos y pinning de fingerprint. La conexión manual al router requiere configurar las variables anteriores.
