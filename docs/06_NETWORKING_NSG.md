# 06 — Networking & NSG Configuration

> SSH tunnel access, NSG lockdown, port configuration.

## Security Model

The Network Analyzer has **no public web ports open**. All access is through an encrypted SSH tunnel:

1. User runs `az ssh vm ... -- -L 8080:localhost:8080 -N` to create a tunnel
2. User opens `http://localhost:8080` in their browser
3. All traffic flows encrypted through SSH — never exposed on the public internet
4. The LLM (Ollama) only listens on `localhost:11434` — also never exposed

## Current Network Setup

| Component | Value |
|---|---|
| **VNet** | <YOUR-VNET> |
| **Subnet** | <YOUR-SUBNET> |
| **VM NIC** | <YOUR-VM-NIC> |
| **Public IP** | <YOUR-VM-PUBLIC-IP> (Static) |
| **VM-Level NSG** | <YOUR-VM-NSG> |
| **Subnet-Level NSG** | <YOUR-SUBNET-NSG> |

> **Important:** There are TWO NSGs — both must allow traffic. The VM-level NSG AND the subnet-level NSG are evaluated. Traffic must pass BOTH.

---

## Current NSG Rules (LOCKED DOWN)

### VM-Level NSG: `<YOUR-VM-NSG>`

| Name | Port | Source | Priority | Access |
|---|---|---|---|---|
| Allow-SSH | 22 | * | 100 | Allow |

**That's it.** All other inbound rules (Allow-WebUI, Allow-Ollama, Allow-VPN-LLM, Allow-WebAnalyzer) have been **deleted**.

### Subnet-Level NSG: `<YOUR-SUBNET-NSG>`

| Name | Port | Source | Priority | Access |
|---|---|---|---|---|
| Allow-SSH | 22 | * | 100 | Allow |

Same — only SSH allowed at the subnet level.

---

## SSH Tunnel Access (Primary Access Method)

### Start the Tunnel

```powershell
# This connects via Azure CLI — works even on VPN (routes through Azure control plane)
az ssh vm --resource-group <YOUR-RESOURCE-GROUP> --name <YOUR-VM-NAME> --local-user <YOUR-USERNAME> -- -L 8080:localhost:8080 -N
```

Keep this terminal open. Then browse to `http://localhost:8080`.

### How It Works

```
Your Browser → http://localhost:8080
    ↓ (local loopback)
SSH Tunnel (encrypted) → Port 22 → VM
    ↓ (localhost forwarding inside VM)
Flask app on VM port 8080
```

### Why `az ssh vm` Instead of Direct SSH?

- **Works on VPN** — `az ssh vm` routes through the Azure control plane, bypassing any VPN routing that would block direct SSH to the public IP
- **No host route needed** — no `route add` or admin elevation required
- **Key management** — Azure CLI handles key exchange automatically

### Verify Tunnel Is Working

```powershell
# In a separate terminal while tunnel is running:
$r = Invoke-WebRequest -Uri "http://localhost:8080" -TimeoutSec 10 -UseBasicParsing
Write-Host "HTTP $($r.StatusCode), $($r.Content.Length) bytes"
```

---

## Ports Used

| Port | Service | Accessibility |
|---|---|---|
| 22 | SSH | External (NSG allows inbound) — used for tunnel |
| 8080 | Network Analyzer Web UI | **Internal only** — localhost on VM, accessed via SSH tunnel |
| 11434 | Ollama API | **Internal only** — localhost on VM, app calls locally |

---

## Modifying NSG Rules

### List Current Rules

```powershell
# VM-level NSG
az network nsg rule list --resource-group <YOUR-RESOURCE-GROUP> --nsg-name <YOUR-VM-NSG> -o table

# Subnet-level NSG
az network nsg rule list --resource-group <YOUR-RESOURCE-GROUP> --nsg-name <YOUR-SUBNET-NSG> -o table
```

### Restrict SSH to Specific IPs (Production Hardening)

```powershell
# Replace * with your corporate IP range
az network nsg rule update `
  --resource-group <YOUR-RESOURCE-GROUP> `
  --nsg-name <YOUR-VM-NSG> `
  --name Allow-SSH `
  --source-address-prefixes "YOUR.CORP.IP.RANGE/24"

# Do the same on the subnet NSG
az network nsg rule update `
  --resource-group <YOUR-RESOURCE-GROUP> `
  --nsg-name <YOUR-SUBNET-NSG> `
  --name Allow-SSH `
  --source-address-prefixes "YOUR.CORP.IP.RANGE/24"
```

### Add a Rule (if ever needed)

```powershell
az network nsg rule create `
  --resource-group <YOUR-RESOURCE-GROUP> `
  --nsg-name <YOUR-VM-NSG> `
  --name <RuleName> `
  --priority <100-4096> `
  --direction Inbound `
  --access Allow `
  --protocol Tcp `
  --destination-port-ranges <port> `
  --source-address-prefixes <IP or *>
```

> **Remember:** Any rule added to the VM NSG must also be mirrored on the subnet NSG if traffic needs to pass through.

---

## Why No Public Web Ports?

- **Data privacy** — customer PCAP/HAR files contain sensitive network traffic; SSH encryption ensures nothing is exposed
- **No attack surface** — only SSH (port 22) is reachable; no web vulnerabilities to exploit
- **Azure internal subscription** — the VM runs in our internal sub, and the open-source LLM means no data leaves the VM
- **Compliance** — encrypted access via SSH tunnel satisfies security review requirements
