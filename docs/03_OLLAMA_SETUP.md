# 03 — Ollama Setup & Model Management

> Install Ollama, configure GPU acceleration, manage LLM models.

## What is Ollama?

Ollama is a local LLM runtime that runs open-source models (Llama, Mistral, etc.) directly on your GPU. No API keys, no cloud calls — all inference happens on the VM.

**Current Setup:**
- Ollama version: 0.16.2
- Model: llama3.1:latest (Meta Llama 3.1 8B, Q4_K_M quantization, 4.9 GB) — open-source, no API keys
- GPU: Tesla T4 (16 GB VRAM) — model runs entirely in GPU memory
- Endpoint: http://localhost:11434 (internal only — not exposed via NSG)

---

## Installation

```bash
# Install Ollama (run on the VM)
curl -fsSL https://ollama.com/install.sh | sh
```

Via `az vm run-command`:
```powershell
az vm run-command invoke --resource-group <YOUR-RESOURCE-GROUP> --name <YOUR-VM-NAME> --command-id RunShellScript --scripts "curl -fsSL https://ollama.com/install.sh | sh"
```

## Systemd Service

Ollama installs its own systemd service automatically:

```ini
# /etc/systemd/system/ollama.service
[Unit]
Description=Ollama Service
After=network-online.target

[Service]
ExecStart=/usr/local/bin/ollama serve
User=ollama
Group=ollama
Restart=always
RestartSec=3
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin"

[Install]
WantedBy=default.target
```

### Manage the Service

```bash
systemctl status ollama          # Check status
systemctl restart ollama         # Restart
systemctl stop ollama            # Stop
journalctl -u ollama -n 50       # View logs
```

---

## Model Management

### Pull a Model

```bash
ollama pull llama3.1              # 8B params, ~4.9 GB (current)
ollama pull llama3.1:70b          # 70B params, ~40 GB (requires 2+ GPUs)
ollama pull mistral               # Mistral 7B, ~4.1 GB
ollama pull codellama             # Code Llama 7B
```

### List Installed Models

```bash
ollama list
```

Output:
```
NAME               ID              SIZE      MODIFIED
llama3.1:latest    46e0c10c039e    4.9 GB    8 days ago
```

### Remove a Model

```bash
ollama rm <model-name>
```

### Test a Model

```bash
# Interactive chat
ollama run llama3.1

# API test
curl http://localhost:11434/api/generate -d '{
  "model": "llama3.1",
  "prompt": "Hello, what can you do?",
  "stream": false
}'
```

---

## GPU Configuration

### Verify GPU is Available

```bash
nvidia-smi
```

Expected: `Tesla T4 | 16384MiB`

### Check Ollama GPU Usage

```bash
# While model is loaded, check VRAM usage
nvidia-smi --query-gpu=memory.used,memory.total --format=csv
```

Llama 3.1 8B uses ~5 GB VRAM on T4.

### Force GPU Layer Count

If Ollama isn't using GPU fully, set via environment:

```bash
# In ollama.service, add:
Environment="OLLAMA_NUM_GPU=999"
```

---

## Model Recommendations

| Use Case | Model | Size | VRAM Needed | Quality |
|---|---|---|---|---|
| **Current (dev)** | llama3.1 (8B) | 4.9 GB | ~5 GB | Good |
| **Better analysis** | llama3.1 (8B) | 4.9 GB | ~5 GB | Good |
| **Best analysis** | llama3.1:70b | ~40 GB | ~42 GB | Excellent |
| **Code focus** | codellama | 4.1 GB | ~5 GB | Good for code |
| **Fast/light** | mistral (7B) | 4.1 GB | ~5 GB | Good |
| **Balanced** | llama3.1 (8B) | 4.9 GB | ~5 GB | Best value |

> **Note:** The T4 has 16 GB VRAM. Any model under ~14 GB will run entirely on GPU. For 70B models, you need 2-4 GPUs (NC64as_T4_v4) or an A100 VM.

---

## Changing the Model Used by the App

The network analyzer reads the model name from the environment:

1. Update the systemd service:
```bash
# Edit the service file
sudo nano /etc/systemd/system/network-analyzer.service

# Change this line:
Environment=OLLAMA_MODEL=llama3.1
# To:
Environment=OLLAMA_MODEL=mistral
```

2. Reload and restart:
```bash
systemctl daemon-reload
systemctl restart network-analyzer
```

Or via `az vm run-command`:
```powershell
az vm run-command invoke --resource-group <YOUR-RESOURCE-GROUP> --name <YOUR-VM-NAME> --command-id RunShellScript --scripts "
sed -i 's/OLLAMA_MODEL=llama3.1/OLLAMA_MODEL=mistral/' /etc/systemd/system/network-analyzer.service
systemctl daemon-reload
systemctl restart network-analyzer
"
```

---

## Ollama API Reference

The network analyzer communicates with Ollama via REST API:

| Endpoint | Method | Purpose |
|---|---|---|
| `http://localhost:11434/api/generate` | POST | Generate text (single prompt) |
| `http://localhost:11434/api/chat` | POST | Chat with conversation history |
| `http://localhost:11434/api/tags` | GET | List available models |
| `http://localhost:11434/api/show` | POST | Get model details |
| `http://localhost:11434/api/pull` | POST | Pull a model |

### Example API call (what the app sends):

```json
POST http://localhost:11434/api/chat
{
  "model": "llama3.1",
  "messages": [
    {"role": "system", "content": "You are a network engineer..."},
    {"role": "user", "content": "Analyze this PCAP: {analysis_data}"}
  ],
  "stream": false
}
```

---

## Updating Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
systemctl restart ollama
ollama --version
```

This updates Ollama in-place without losing downloaded models.
