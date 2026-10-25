# OpenWrt-MCP

Local `stdio` MCP for managing OpenWrt routers over SSH. The server runs on your PC, connects only to a private LAN or Tailscale IP, and does not open any ports on the router.

## Requirements

- Node.js 20 or higher.
- SSH enabled on OpenWrt and the client's public key authorized on the router.
- A routable private LAN or Tailscale (CGNAT `100.64.0.0/10`) IP. For remote use over Tailscale, the router must be connected to your tailnet and the firewall must allow SSH from the tailnet.
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

- `OPENWRT_HOST`: router's private IP, for example `192.168.1.1` or a Tailscale IP such as `100.64.1.2`.
- `OPENWRT_SSH_PORT`: SSH port (optional, defaults to `22`).
- `OPENWRT_SSH_USER`: SSH user, often `root` on OpenWrt.
- `OPENWRT_SSH_KEY_PATH`: path to the private key authorized on OpenWrt.
- `OPENWRT_SSH_KEY_PASSPHRASE`: key passphrase, optional.
- `OPENWRT_SSH_HOST_FINGERPRINT`: pinned fingerprint in `SHA256:...` format.
- `OPENWRT_TAILSCALE_AUTHKEY`: optional Tailscale auth key (`tskey-...`), recommended over passing the key in tool input. It is read from the MCP process environment and never echoed back.

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

Use a private LAN/Tailscale IP for each target; do not clone a configuration by only changing the label. Do not store private keys, auth keys, or passphrases in the repository.

## Tools

- `get_router_status(section)`: predefined read for `system`, `storage`, `interfaces`, `wireless`, `clients`, or `logs`.
- `get_device_capabilities()`: reads OpenWrt version/target, detected package managers (`apk`/`opkg`), available tools (including `tailscale`/`tailscaled`), interface names, routes, and pending UCI changes. The configuration hash is computed on the router.
- `get_tailscale_status()`: reads installation, daemon state, backend state, node IPs, advertised routes, exit node, and peer counts. Makes no changes.
- `plan_tailscale_up(...)`: validates and previews a Tailscale node configuration (`hostname`, `advertiseRoutes`, `advertiseExitNode`, `acceptRoutes`, `acceptDns`, optional `authKey`) and returns a summary with an approval digest. Does not change the router. The auth key is never echoed back.
- `apply_tailscale_up(planId, digest)`: applies only the previous plan, as long as the same MCP process is alive and the configuration has not changed. Runs `tailscale up` with only the planned flags and changes the router's Tailscale state. Requires approval from the MCP client. It does not install packages.
- `verify_tailscale()`: on a fresh SSH connection, confirms the daemon is running, the backend state is `Running`, the node has assigned IPs, and reports advertised routes, exit node, and the `tailscale0` address.
- `execute_command(command, confirm)`: advanced SSH shell tool. Literal repetition of `confirm` **is not human approval nor a sandbox**; it can change the configuration or interrupt access.

### Conversational Tailscale flow

First ask for `get_device_capabilities` and `get_tailscale_status`, then describe the node and request `plan_tailscale_up`. Review the hostname, advertised routes, exit-node flag, and digest in the response. To connect the router, explicitly request `apply_tailscale_up` with the `planId` and digest of the approved plan; finish with `verify_tailscale` from a new connection. Nothing is changed when the MCP starts.

Preferred secret handling: set `OPENWRT_TAILSCALE_AUTHKEY` in the MCP client environment instead of putting the key in the tool input, so it never appears in conversation logs. During apply the key is sent over SSH stdin, written to a `chmod 600` temporary file, passed as `--auth-key=file:...`, and deleted by an `EXIT` trap. The plan's key lives in MCP memory for a maximum of 10 minutes; if the server restarts between plan and apply, create a new plan.

Route advertisements are validated: `0.0.0.0/0` and `::/0` are rejected (use `advertiseExitNode`), as are the reserved tailnet ranges `100.64.0.0/10` and `fd7a:115c:a1e0::/48`, duplicates, and invalid CIDRs. The MCP never installs or updates packages; if `tailscale`/`tailscaled` are missing, install the package with the device package manager first. Only the `tailscaled` service is started, and only if it is not already running. The firewall is not modified, so subnet-router or exit-node traffic may still need firewall changes through a reviewed `execute_command`.

There is no general rollback or recovery guarantee if the system becomes unreachable. Do not run sessions with `--yolo`; mutable tools must have approval in the MCP client. SSH per-call timeout: 30 seconds for reads and 60 seconds for apply; maximum combined output: 32 KiB.

## Experimental status and pending items

Tailscale support is new. Capability detection, status parsing, plan validation, script generation, and secret redaction are covered by unit tests. `apply_tailscale_up` has **not yet been validated against a real router running `tailscaled`**, and `tailscale up` output can vary across OpenWrt releases. Verify with `verify_tailscale` before relying on the tunnel as your only access path.

## Development and testing

```powershell
npm.cmd run typecheck
npm.cmd test
npm.cmd run build
```

The tests cover private IP validation, command confirmation, fingerprint pinning, Tailscale status parsing, plan validation, script generation, and auth-key redaction. The manual connection to the router requires configuring the variables above.
