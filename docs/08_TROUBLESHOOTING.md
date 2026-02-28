# 08 — Troubleshooting Guide

> Common issues and how to fix them.

## Quick Diagnostic Commands

```powershell
# Set target
$RG = "<YOUR-RESOURCE-GROUP>"
$VM = "<YOUR-VM-NAME>"

# Check VM power state
az vm show --resource-group $RG --name $VM --show-details --query powerState -o tsv

# Check all services
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "
echo '=== Network Analyzer ==='
systemctl status network-analyzer --no-pager | head -10
echo ''
echo '=== Ollama ==='
systemctl status ollama --no-pager | head -10
echo ''
echo '=== GPU ==='
nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader
echo ''
echo '=== Disk ==='
df -h /data
echo ''
echo '=== Port 8080 ==='
ss -tlnp | grep 8080
"
```

---

## Issue: Portal Won't Load

### SSH tunnel not running
The portal is only accessible via SSH tunnel. Make sure you have this running in a separate terminal:
```powershell
az ssh vm --resource-group <YOUR-RESOURCE-GROUP> --name <YOUR-VM-NAME> --local-user <YOUR-USERNAME> -- -L 8080:localhost:8080 -N
```
Then open `http://localhost:8080` in your browser.

### VM is stopped
```powershell
az vm start --resource-group $RG --name $VM
# Wait 2-3 minutes for services to start
```

### Service is crashed
```powershell
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "
journalctl -u network-analyzer -n 50 --no-pager
"
```

Fix: Check the logs for Python errors, fix the code, redeploy.

### Port blocked by NSG
Port 8080 is intentionally NOT open in the NSG. Access is via SSH tunnel only.
Verify SSH (port 22) is allowed:
```powershell
az network nsg rule list --resource-group $RG --nsg-name <YOUR-VM-NSG> -o table
# Ensure port 22 has an Allow rule
```

### Service crashed but tunnel connects
If the tunnel connects (no error) but the page doesn't load, the Flask app may have crashed:
```powershell
az ssh vm --resource-group $RG --name $VM --local-user <YOUR-USERNAME> -- "sudo systemctl restart ollama; sleep 3; sudo systemctl restart network-analyzer; sleep 2; sudo systemctl status network-analyzer --no-pager | head -5"
```

---

## Issue: "LLM Ready" Badge is Red / Missing

### Ollama not running
```powershell
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "
systemctl status ollama --no-pager
systemctl restart ollama
sleep 5
curl -s http://localhost:11434/api/tags
"
```

### Model not downloaded
```powershell
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "
ollama list
# If empty:
ollama pull llama3.1
"
```

### GPU driver issue
```powershell
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "nvidia-smi"
# If fails, reinstall drivers:
# apt-get install -y ubuntu-drivers-common && ubuntu-drivers install
# Then reboot
```

---

## Issue: File Upload Doesn't Work

### File dialog doesn't open
- Hard refresh: `Ctrl+Shift+R` at `http://localhost:8080`
- Try InPrivate/Incognito window
- Check browser console (F12) for JavaScript errors
- Common cause: JS syntax error in the script block (see below)

### File selected but nothing happens
- This is usually a JS crash: the `<script>` block has a syntax error
- Common cause: `\n` in Python source not double-escaped for JS regex
- Check: `curl.exe -s http://<YOUR-VM-PUBLIC-IP>:8080 | Select-String "formatMarkdown" | Select-Object -First 5`
- The regex patterns should have `\n` NOT a literal newline on a new line

### Fix JS regex escaping
In the Python source, inside `HTML_TEMPLATE = """..."""`:
- **Bad:** `text.replace(/\n/g, '<br>')` (Python interprets `\n` as newline)
- **Good:** `text.replace(/\\n/g, '<br>')` (Python outputs literal `\n`)

---

## Issue: Session History Not Working

### Sessions not appearing in History panel
```powershell
# Check if sessions directory exists and has files
az ssh vm --resource-group $RG --name $VM --local-user <YOUR-USERNAME> -- "ls -la /data/network-analyzer/sessions/"
```

### Sessions lost after restart
Sessions are saved as JSON files in `/data/network-analyzer/sessions/`. They survive restarts.
If the directory was deleted, recreate it:
```powershell
az ssh vm --resource-group $RG --name $VM --local-user <YOUR-USERNAME> -- "mkdir -p /data/network-analyzer/sessions && sudo systemctl restart network-analyzer"
```

### /sessions API returning errors
```powershell
# Test the API directly
$r = Invoke-WebRequest -Uri "http://localhost:8080/sessions" -UseBasicParsing -TimeoutSec 10
Write-Host $r.Content
```

---

## Issue: Analysis Takes Too Long / Timeouts

### Ollama is slow
```powershell
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "
nvidia-smi
# Check if GPU is being used (memory should show ~5GB for llama3.1)
"
```

If memory.used is 0, Ollama may be running on CPU. Restart:
```bash
systemctl restart ollama
sleep 10
ollama run llama3.1 'hello'  # warm up the model
```

### Large PCAP file
- Files > 100 MB may take longer to parse
- The analysis is done in-memory with Scapy
- Consider adding a file size limit in the UI

---

## Issue: Emojis Show as Garbled Characters

This happens when Unicode characters get corrupted during base64 encoding.

**Fix:** Replace raw emojis with HTML entities in the Python source:
- 📁 → `&#x1F4C1;`
- 📎 → `&#x1F4CE;`
- 📊 → `&#x1F4CA;`
- 📡 → `&#x1F4E1;`
- 🔍 → `&#x1F50D;`
- 📦 → `&#x1F4E6;`

And in JavaScript code, use `\\u2022` instead of `•`.

---

## Issue: Disk Full

```powershell
az ssh vm --resource-group $RG --name $VM --local-user <YOUR-USERNAME> -- "
df -h
du -sh /data/*
du -sh /data/network-analyzer/sessions/
# Clean up old sessions if needed
ls -la /data/network-analyzer/sessions/ | head -20
# Clean up old uploads
rm -rf /data/network-analyzer/uploads/*
"
```

---

## Issue: Spot VM Was Evicted

Spot VMs can be deallocated by Azure when capacity is needed.

```powershell
# Check status
az vm show --resource-group $RG --name $VM --show-details --query powerState -o tsv

# If deallocated, restart
az vm start --resource-group $RG --name $VM
# Note: public IP may change if not static! Check:
az vm show --resource-group $RG --name $VM --show-details --query publicIps -o tsv
```

For production, switch to Regular priority VMs.

---

## Viewing Logs

### Network Analyzer logs
```powershell
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "journalctl -u network-analyzer -n 100 --no-pager"
```

### Ollama logs
```powershell
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "journalctl -u ollama -n 100 --no-pager"
```

### System logs
```powershell
az vm run-command invoke --resource-group $RG --name $VM --command-id RunShellScript --scripts "dmesg | tail -50"
```
