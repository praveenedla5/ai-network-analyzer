# 05 — Adding Features to the Network Analyzer

> How to add PCAP/HAR analysis features, UI changes, or LLM customizations without breaking existing functionality.

## Code Architecture (Single File)

```
network_analyzer.py (~1600 lines)
│
├── Lines 1-22:      Imports (Flask, Scapy, Haralyzer, requests, json, os, etc.)
├── Lines 23-46:     Constants (OLLAMA_URL, OLLAMA_MODEL, PORT, UPLOAD_FOLDER, SESSIONS_FOLDER)
├── Lines 47-120:    Session persistence functions (save_session, load_session, list_sessions)
│                    └── Sessions saved as JSON files in /data/network-analyzer/sessions/
│
├── Lines ~120-300:  analyze_pcap_detailed(filepath) → dict
│                    Parses PCAP with Scapy → packets, protocols, TCP flags, IPs, DNS, retransmissions
│
├── Lines ~300-440:  analyze_har_detailed(filepath) → dict
│                    Parses HAR with Haralyzer → requests, status codes, timing, domains
│
├── Lines ~440-490:  query_llm(prompt, analysis_data, conversation_id) → str
│                    Sends analysis + prompt to Ollama, manages conversation history + session persistence
│
├── Lines ~490-1350: HTML_TEMPLATE = """..."""
│   ├── CSS:         Dark theme styles, history panel, new session button (~lines 500-940)
│   ├── HTML:        Header (status + New Session + History), chat UI, history sidebar,
│   │                analysis panel (~lines 940-1020)
│   └── JavaScript:  Session history (toggle, load, delete, render), new session,
│                    file upload, chat, analysis display (~lines 1020-1340)
│
├── Lines ~1350-1430: Flask Routes
│   ├── GET /              → Serves HTML_TEMPLATE
│   ├── GET /health        → Health check JSON
│   ├── POST /analyze      → File + message → analysis + LLM response (also persists session)
│   ├── POST /clear        → Clear conversation (supports per-session or all)
│   ├── GET /sessions      → List all saved sessions
│   ├── GET /sessions/<id> → Load full session data
│   └── DELETE /sessions/<id> → Delete a session
│
└── Lines ~1430-1450: Main entry point (app.run 0.0.0.0:8080)
```

---

## Where to Edit for Each Type of Change

| What You Want | Where to Edit |
|---|---|
| **New PCAP metrics** (TLS, HTTP, QUIC) | `analyze_pcap_detailed()` — lines ~120-300 |
| **New HAR metrics** (cache, CORS, cookies) | `analyze_har_detailed()` — lines ~300-440 |
| **Change LLM prompt/behavior** | `query_llm()` — lines ~440-490 |
| **Change UI look/colors** | CSS in `HTML_TEMPLATE` — lines ~500-940 |
| **Add UI elements** (buttons, panels) | HTML in `HTML_TEMPLATE` — lines ~940-1020 |
| **Change UI behavior** (new JS features) | JavaScript in `HTML_TEMPLATE` — lines ~1020-1340 |
| **Show new metrics in analysis panel** | `updateAnalysisPanel()` JS function — lines ~1280-1340 |
| **Add API endpoints** | Flask routes — lines ~1350-1430 |
| **Session persistence logic** | `save_session()`, `load_session()` — lines ~47-120 |

---

## Step-by-Step: Adding a Feature

### 1. Edit Locally

Open: `src/network_analyzer.py`

### 2. Make Your Change

(See examples below)

### 3. Test Locally (Optional)

```bash
python network_analyzer.py
# Opens at http://localhost:8080
# LLM calls will fail but UI changes work
```

### 4. Deploy

```powershell
$content = Get-Content -Path "src/network_analyzer.py" -Raw -Encoding UTF8
$b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($content))
$script = "#!/bin/bash`necho '$b64' | base64 -d > /data/network-analyzer/network_analyzer.py`nmkdir -p /data/network-analyzer/sessions`nsudo systemctl restart network-analyzer`nsleep 2`nsudo systemctl status network-analyzer --no-pager | head -5`necho '---'`ncurl -s -o /dev/null -w '%{http_code}' http://localhost:8080"
Set-Content -Path "$env:TEMP\deploy_na.sh" -Value $script -Encoding UTF8 -NoNewline
$scriptPath = "$env:TEMP\deploy_na.sh"
az vm run-command invoke --resource-group <YOUR-RESOURCE-GROUP> --name <YOUR-VM-NAME> --command-id RunShellScript --scripts "@$scriptPath"
```

### 5. Verify

- Make sure SSH tunnel is running (`az ssh vm ... -- -L 8080:localhost:8080 -N`)
- Hard refresh: `Ctrl+Shift+R` at `http://localhost:8080`
- Test upload and analysis still works
- Test your new feature
- Check 📋 History to confirm session persistence still works

---

## Example: Add TLS Version Detection (PCAP)

In `analyze_pcap_detailed()`, after the protocol counting loop:

```python
# TLS version detection
tls_versions = {}
for pkt in packets:
    if pkt.haslayer('TLS'):
        ver = pkt['TLS'].version
        tls_versions[ver] = tls_versions.get(ver, 0) + 1
analysis['tls_versions'] = tls_versions
```

Then in `updateAnalysisPanel()` JS, add a new card:

```javascript
if (analysis.tls_versions && Object.keys(analysis.tls_versions).length > 0) {
    html += `<div class="analysis-card">
        <h4>TLS Versions</h4>
        <div class="stat-grid">
            ${Object.entries(analysis.tls_versions).map(([k,v]) =>
                `<div class="stat-item"><label>${k}</label><span>${v}</span></div>`
            ).join('')}
        </div>
    </div>`;
}
```

## Example: Add Response Size Analysis (HAR)

In `analyze_har_detailed()`:

```python
# Response size analysis
sizes = [e['response']['bodySize'] for e in har_data['log']['entries'] if e['response']['bodySize'] > 0]
analysis['response_sizes'] = {
    'total_bytes': sum(sizes),
    'avg_bytes': int(sum(sizes) / len(sizes)) if sizes else 0,
    'max_bytes': max(sizes) if sizes else 0
}
```

## Example: Change LLM System Prompt

In `query_llm()`, modify the `system_prompt`:

```python
system_prompt = """You are a senior network engineer specializing in Azure networking.
Focus on: TCP retransmissions, DNS failures, TLS handshake issues, and latency.
Always suggest specific next steps for troubleshooting.
Format your response with clear sections and bullet points."""
```

## Example: Add a New Python Package

```powershell
# Install on VM first
az vm run-command invoke --resource-group <YOUR-RESOURCE-GROUP> --name <YOUR-VM-NAME> --command-id RunShellScript --scripts "pip3 install <package> --break-system-packages"

# Then add import to network_analyzer.py and deploy
```

---

## Critical Gotchas

### 1. Python Triple-Quoted String Escaping

The HTML is inside `"""..."""`. Python interprets escape sequences!

| In JS you want | Write in Python source |
|---|---|
| `\n` (in regex) | `\\n` |
| `\t` | `\\t` |
| `\d` | `\\d` |
| `\s` | `\\s` |

**Bad:** `text.replace(/\n/g, '<br>')` — Python turns `\n` into a real newline, breaking JS

**Good:** `text.replace(/\\n/g, '<br>')` — Python outputs `\n` in the HTML

### 2. Emoji / Unicode Characters

Don't use raw emojis like 📁 — base64 encoding corrupts them.

Use HTML entities instead:
- 📁 → `&#x1F4C1;`
- 📎 → `&#x1F4CE;`
- 📊 → `&#x1F4CA;`
- 📡 → `&#x1F4E1;`

Or JS Unicode escapes in JavaScript code:
- `•` → `\\u2022`

### 3. Backticks in JS

Template literals (`` `text ${var}` ``) work fine inside Python `"""..."""` strings. No escaping needed.

### 4. Testing Before Deploy

Run locally to test UI changes (Ollama calls will fail):
```bash
python network_analyzer.py
# Browser → http://localhost:8080
```

### 5. If You Add New Python Imports

Install on the VM first:
```powershell
az vm run-command invoke --resource-group <YOUR-RESOURCE-GROUP> --name <YOUR-VM-NAME> --command-id RunShellScript --scripts "pip3 install <package> --break-system-packages"
```
