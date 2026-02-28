# 04 — App Deployment Guide

> How to deploy or update the Network Analyzer application to any VM.

## Deployment Method: Base64 via az vm run-command

We use `az vm run-command invoke` to deploy without needing SSH access. The Python file is base64-encoded locally, transferred as a shell script, and decoded on the VM.

---

## Deploy / Update the App (Copy-Paste Ready)

The Python file is base64-encoded into a temp shell script, then executed on the VM via `az vm run-command invoke`.

```powershell
# === CONFIGURE TARGET ===
$RG = "<YOUR-RESOURCE-GROUP>"       # Resource group
$VM = "<YOUR-VM-NAME>"             # VM name

# === ENCODE ===
$content = Get-Content -Path "src/network_analyzer.py" -Raw -Encoding UTF8
$b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($content))

# === BUILD DEPLOY SCRIPT (file-based to avoid command-line length limits) ===
$script = "#!/bin/bash`necho '$b64' | base64 -d > /data/network-analyzer/network_analyzer.py`nmkdir -p /data/network-analyzer/sessions`nsudo systemctl restart network-analyzer`nsleep 2`nsudo systemctl status network-analyzer --no-pager | head -5`necho '---'`ncurl -s -o /dev/null -w '%{http_code}' http://localhost:8080"
Set-Content -Path "$env:TEMP\deploy_na.sh" -Value $script -Encoding UTF8 -NoNewline

# === EXECUTE ON VM ===
$scriptPath = "$env:TEMP\deploy_na.sh"
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "@$scriptPath"
```

> **Why file-based?** The base64 payload is ~90KB. Passing it inline on the command line hits Windows' 32K character limit. Writing to a temp file and using `@$scriptPath` avoids this.

### After Deployment

1. Check output for `Active: active (running)` and HTTP `200`
2. If your SSH tunnel is running, hard refresh browser: `Ctrl+Shift+R` on `http://localhost:8080`
3. Test a file upload to verify functionality
4. Click 📋 History to verify session persistence is working

---

## First-Time Setup on a New VM

If the VM has never had the app installed, do these steps first:

### 1. Install Python Dependencies

```powershell
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "
pip3 install flask scapy haralyzer requests --break-system-packages
"
```

### 2. Create App Directory

```powershell
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "mkdir -p /data/network-analyzer"
```

### 3. Deploy the App (use the deploy script above)

### 4. Create Systemd Service

```powershell
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "
cat > /etc/systemd/system/network-analyzer.service << 'EOF'
[Unit]
Description=Network Traffic Analyzer
After=network.target ollama.service

[Service]
Type=simple
User=root
WorkingDirectory=/data/network-analyzer
Environment=OLLAMA_URL=http://localhost:11434
Environment=OLLAMA_MODEL=llama3.1
Environment=PORT=8080
ExecStart=/usr/bin/python3 /data/network-analyzer/network_analyzer.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable network-analyzer
systemctl start network-analyzer
"
```

---

## Check Service Status

```powershell
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "systemctl status network-analyzer --no-pager"
```

## View Logs

```powershell
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "journalctl -u network-analyzer -n 100 --no-pager"
```

## Restart Service

```powershell
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "systemctl restart network-analyzer && sleep 2 && systemctl status network-analyzer --no-pager"
```

---

## Application File Structure on VM

```
/data/network-analyzer/
├── network_analyzer.py     # Single-file Flask app (~1600 lines)
└── sessions/               # Persistent session JSON files
    ├── session_1740691234.json
    ├── session_1740695678.json
    └── ...
```

The app serves everything from one file — HTML, CSS, JavaScript, Flask routes, Scapy/Haralyzer analysis, LLM integration, and session persistence. Session history is saved as JSON files in the `sessions/` directory.

---

## Environment Variables

The systemd service sets these environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_URL` | http://localhost:11434 | Ollama API endpoint |
| `OLLAMA_MODEL` | llama3.1 | Which LLM model to use |
| `PORT` | 8080 | Web server port |
| `UPLOAD_FOLDER` | /data/network-analyzer/uploads | Where uploaded files are stored |
| `SESSIONS_FOLDER` | /data/network-analyzer/sessions | Where session JSON files persist |

To change, edit `/etc/systemd/system/network-analyzer.service` then:
```bash
systemctl daemon-reload
systemctl restart network-analyzer
```

---

## Quick Copilot Context Prompt

When starting a new Copilot session to modify the app, paste this:

> _"I have a network PCAP/HAR analyzer running on Azure VM `<YOUR-VM-NAME>` (RG: `<YOUR-RESOURCE-GROUP>`). Access is via SSH tunnel only (`az ssh vm ... -- -L 8080:localhost:8080 -N` → `http://localhost:8080`). The source code is at `src/network_analyzer.py`. It's a single-file Flask app (~1600 lines) with inline HTML/JS that uses Ollama (llama3.1) for LLM analysis. It has session history persistence to `/data/network-analyzer/sessions/`. Python triple-quoted string for HTML — must double-escape \n in JS regex. Deploy via base64 + file-based `az vm run-command invoke`. I need you to [DESCRIBE YOUR CHANGE]."_
