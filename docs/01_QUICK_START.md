# 01 — Quick Start: Using the Network Analyzer

## Step 1: Start the SSH Tunnel

The portal is only accessible through an encrypted SSH tunnel. No public web ports are open.

```powershell
# Open an SSH tunnel (keep this terminal running)
az ssh vm --resource-group <YOUR-RESOURCE-GROUP> --name <YOUR-VM-NAME> --local-user <YOUR-USERNAME> -- -L 8080:localhost:8080 -N
```

> **Note:** This uses Azure CLI's `az ssh vm` which works even on VPN — it routes through the Azure control plane, not via the public IP directly.

## Step 2: Open the Portal

1. Open a browser and go to: **http://localhost:8080**
2. Verify the **LLM Ready** badge is green in the header (means Ollama + GPU model is loaded)

## Analyze a PCAP File

1. Click the **"Click to upload"** zone (or drag & drop a file)
2. Select a `.pcap`, `.cap`, or `.har` file
3. The filename appears in the upload area
4. (Optional) Type a specific question like _"What is causing the retransmissions?"_
5. Click **Analyze**
6. Wait for the LLM to respond (10-30 seconds depending on file size)
7. View results in the **chat** (left) and **Latest Analysis panel** (right)

## Ask Follow-up Questions

After the initial analysis, type questions in the chat:
- "What are the top talkers by IP?"
- "Are there any DNS resolution failures?"
- "What could be causing the RST packets?"
- "Which requests have the highest latency?"
- "Summarize the main issues found"

The LLM remembers the context of your analysis session.

## New Session

Click **🔄 New Session** in the header bar to reset everything and start a fresh analysis — no need to open a new browser window.

## Session History

Click **📋 History** in the header bar to open the session history sidebar. All your past sessions are saved automatically and persist across server restarts.

From the history panel you can:
- **Click any session** to reload it — chat messages, analysis panel, and conversation context all restore
- **Delete a session** by hovering and clicking the 🗑️ icon
- See the file name, file type (📦 PCAP / 🌐 HAR), time ago, and message count for each session

## Supported File Types

| Extension | Type | Parser |
|---|---|---|
| `.pcap` | Packet capture | Scapy |
| `.cap` | Packet capture | Scapy |
| `.har` | HTTP Archive | Haralyzer |

## What Gets Analyzed

### PCAP Files
- Total packet count and capture duration
- Protocol distribution (TCP, UDP, ICMP, DNS, ARP)
- TCP flag analysis (SYN, RST, FIN, ACK)
- Retransmission detection
- Top source/destination IPs
- DNS queries and responses
- Potential anomalies (RST floods, excessive retransmissions, etc.)

### HAR Files
- Total HTTP request count
- Status code distribution (2xx, 3xx, 4xx, 5xx)
- Average/min/max response times
- Domain breakdown
- Content type distribution
- Slow request identification
- Error patterns

## If the Portal Won't Load

1. Make sure the SSH tunnel is running (the `az ssh vm ... -L 8080:localhost:8080 -N` command in a separate terminal)
2. Check VM is running: `az vm show --resource-group <YOUR-RESOURCE-GROUP> --name <YOUR-VM-NAME> --show-details --query powerState -o tsv`
3. Start VM if stopped: `az vm start --resource-group <YOUR-RESOURCE-GROUP> --name <YOUR-VM-NAME>`
4. Wait 2-3 minutes for services to start, then restart the SSH tunnel and refresh
5. If the tunnel connects but the page doesn't load, restart the services on the VM:

```powershell
az ssh vm --resource-group <YOUR-RESOURCE-GROUP> --name <YOUR-VM-NAME> --local-user <YOUR-USERNAME> -- "sudo systemctl restart ollama; sleep 3; sudo systemctl restart network-analyzer; sleep 2; sudo systemctl status network-analyzer --no-pager | head -5"
```
