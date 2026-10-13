# OpenWrt-MCP

Local `stdio` MCP for managing OpenWrt routers over SSH. The server runs on your PC, connects only to a private LAN or WireGuard IP, and does not open any ports on the router.

## Requirements

- Node.js 20 or higher.
- SSH enabled on OpenWrt and the client's public key authorized on the router.
- A routable private LAN or WireGuard IP. For remote use, WireGuard must advertise the route to the router and the firewall must allow SSH from the VPN peer.
- The router's SSH host SHA256 fingerprint, verified through a trusted channel.

The configuration rejects public addresses and DNS names. It checks the SSH host key on every connection. The private key is never included in this repository.

## Installation

In the cloned folder:

```powershell
npm.cmd install
npm.cmd run build
npm.cmd test
```

Set these environment variables on Windows before starting your MCP client:

- `OPENWRT_HOST`: router's private IP, for example `192.168.1.1` or a private WireGuard IP.
- `OPENWRT_SSH_PORT`: SSH port (optional, defaults to `22`).
- `OPENWRT_SSH_USER`: SSH user, often `root` on OpenWrt.
- `OPENWRT_SSH_KEY_PATH`: path to the private key authorized on OpenWrt.
- `OPENWRT_SSH_KEY_PASSPHRASE`: key passphrase, optional.
- `OPENWRT_SSH_HOST_FINGERPRINT`: pinned fingerprint in `SHA256:...` format.

Do not disable fingerprint validation. Get the fingerprint with `ssh-keygen -lf <host-public-key> -E sha256` after verifying the host's public key through a trusted channel.

## Connecting one or more routers from any MCP client

This is a standard `stdio` MCP server, so it works with any MCP-compatible client (Command Code, Claude Code, Antigravity, and others). Register one server instance **per router**: the server name and `OPENWRT_MCP_NAME` form the stable alias your client sees, and each instance has its own IP, key, and fingerprint, so the model cannot implicitly switch routers during an operation.

The generic shape of the configuration is: launch `node <path>/dist/index.js` with the environment variables above.

```json
{
  "mcpServers": {
    "openwrt-home": {
      "command": "node",
      "args": ["C:\\Users\\YOUR_USER\\OpenWrt-MCP\\dist\\index.js"],
      "env": {
        "OPENWRT_MCP_NAME": "openwrt-home",
        "OPENWRT_HOST": "192.168.1.1",
        "OPENWRT_SSH_PORT": "22",
        "OPENWRT_SSH_USER": "root",
        "OPENWRT_SSH_KEY_PATH": "C:\\Users\\YOUR_USER\\.ssh\\openwrt-home",
        "OPENWRT_SSH_HOST_FINGERPRINT": "SHA256:HOME_FINGERPRINT"
      }
    }
  }
}
```

Add another instance with a different alias and independent credentials:

```json
{
  "mcpServers": {
    "openwrt-office": {
      "command": "node",
      "args": ["C:\\Users\\YOUR_USER\\OpenWrt-MCP\\dist\\index.js"],
      "env": {
        "OPENWRT_MCP_NAME": "openwrt-office",
        "OPENWRT_HOST": "10.8.0.1",
        "OPENWRT_SSH_PORT": "22",
        "OPENWRT_SSH_USER": "root",
        "OPENWRT_SSH_KEY_PATH": "C:\\Users\\YOUR_USER\\.ssh\\openwrt-office",
        "OPENWRT_SSH_HOST_FINGERPRINT": "SHA256:OFFICE_FINGERPRINT"
      }
    }
  }
}
```

Where to put this JSON depends on your client — consult its MCP documentation:

- **Command Code**: `cmdc mcp add`, or the same `mcpServers` format via the client's MCP settings.
- **Claude Code**: `claude mcp add`, or `.mcp.json` in the project.
- **Antigravity**: the MCP configuration in its settings.

Use a private LAN/WireGuard IP for each target; do not clone a configuration by only changing the label. Do not store private keys or passphrases in the repository.

## Tools

- `get_router_status(section)`: predefined read for `system`, `storage`, `interfaces`, `wireless`, `clients`, or `logs`.
- `get_device_capabilities()`: reads OpenWrt version/target, detected package managers (`apk`/`opkg`), available tools, interface names, routes, and pending UCI changes. The configuration hash is computed on the router; the MCP does not receive existing private keys.
- `plan_wireguard_tunnel(...)`: validates and previews the creation of a new WireGuard interface. Generates a local key for the tunnel and returns its public key, summary, and approval digest; the private key stays only in the MCP process memory and never appears in the response. Does not change the router.
- `apply_wireguard_tunnel(planId, digest)`: applies only the previous plan, as long as the same MCP process is still alive and the digest/configuration has not changed. Requires approval from the MCP client. Does not touch existing interfaces, firewall, WAN/LAN, or default routes; it detects the package manager but does not install or update packages.
- `verify_wireguard_tunnel(interfaceName)`: verifies on a new SSH connection whether it is configured/active and whether there is a recent handshake. "Up without a handshake" does not mean the remote peer is reachable.
- `execute_command(command, confirm)`: advanced SSH shell tool. Literal repetition of `confirm` **is not human approval nor a sandbox**; it can change the configuration or interrupt access.

### Conversational WireGuard flow

First ask for `get_device_capabilities`, then describe the tunnel and request `plan_wireguard_tunnel`. Review the addresses, AllowedIPs, endpoint, and public key in the response. To create the tunnel, explicitly request `apply_wireguard_tunnel` with the `planId` and digest of the approved plan; finish with `verify_wireguard_tunnel` from a new connection. No tunnel is created or applied when the MCP starts.

The tunnel is deliberately isolated: `0.0.0.0/0` and `::/0`, AllowedIPs that overlap existing routes, already-used names, and pending UCI changes are rejected. The firewall is not modified either, so this first cut creates the local interface/peer but does not guarantee inbound connectivity through WAN zones; endpoint exposure must be configured separately with a specific, reviewed operation.

There is no general rollback or recovery guarantee if the system becomes unreachable. The preview, hash check, and independent verification reduce errors, but they cannot prove the remote peer will work. If the SSH route is lost, recovery may require LAN/local access. Do not run sessions with `--yolo`; mutable tools must have approval in the MCP client. Per-call timeout: 30 seconds; maximum combined output: 32 KiB.

The plan's temporary private key lives in the MCP's memory for a maximum of 10 minutes. If the server restarts between `plan` and `apply`, create a new plan and distribute the new public key to the remote peer.

## Experimental status and pending items

WireGuard configuration is experimental. Capability detection, validation, key generation, local preview, and the shell parser have been tested. `apply_wireguard_tunnel` has been exercised on a laboratory router (creating an interface, completing a remote handshake, and removing it), but it **has not yet been validated in a fully remote, real-world environment**. Do not rely on it as your only access path until that validation is complete.

A plan with `peers: []` only serves to validate the creation of an isolated local interface; it does not establish a handshake. Verifying real connectivity requires a remote peer configured with the generated public key. Pending items: validating in a real remote environment, verifying the real format of UCI changes across releases, and rotating the `wg0` key that was accidentally exposed during the previous diagnosis.

## Development and testing

```powershell
npm.cmd run typecheck
npm.cmd test
npm.cmd run build
```

The tests cover private IP validation, command confirmation, and fingerprint pinning. The manual connection to the router requires configuring the variables above.
