# 07 — Scaling to Production & More Users

> How to scale the Network Analyzer for larger teams.

## Current Setup (Dev/Prototype)

- 1 VM: Standard_NC4as_T4_v3 (4 vCPUs, 28 GB RAM, 1x T4 GPU)
- Flask dev server (single-threaded)
- SSH tunnel access only (no public web ports)
- Supports: 1-5 concurrent users
- No authentication (protected by SSH access control)
- Session history persists to disk
- No HTTPS needed (SSH tunnel provides encryption)

---

## Scaling Steps

### Level 1: Small Team (5-20 users)

**VM:** Stay on NC4as_T4_v3 or upgrade to NC8as_T4_v3

**Add Gunicorn** (multi-worker production server):

```bash
# Install
pip3 install gunicorn --break-system-packages

# Update service file
sudo nano /etc/systemd/system/network-analyzer.service
```

Change `ExecStart` to:
```ini
ExecStart=/usr/local/bin/gunicorn --workers 4 --bind 0.0.0.0:8080 --timeout 300 network_analyzer:app
```

```bash
systemctl daemon-reload
systemctl restart network-analyzer
```

### Level 2: Medium Team (20-50 users)

**VM:** Standard_NC16as_T4_v3 (16 vCPUs, 110 GB RAM, 1x T4)

Additional changes:
- Gunicorn with 8-16 workers
- Add Nginx reverse proxy for HTTPS
- Add Azure AD authentication
- Consider a larger model for better analysis

### Level 3: Large Team (50-100+ users)

**VM:** Standard_NC64as_T4_v4 (64 vCPUs, 440 GB RAM, 4x T4)

Or **multi-VM setup:**
- Azure Application Gateway as load balancer
- 2-4 VMs behind the gateway
- Shared model loading
- Azure AD SSO

---

## Add HTTPS (Nginx Reverse Proxy)

```bash
# Install Nginx
apt install -y nginx

# Configure reverse proxy
cat > /etc/nginx/sites-available/network-analyzer << 'EOF'
server {
    listen 443 ssl;
    server_name your.domain.com;

    ssl_certificate /etc/ssl/certs/your-cert.pem;
    ssl_certificate_key /etc/ssl/private/your-key.pem;

    client_max_body_size 100M;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 300s;
    }
}

server {
    listen 80;
    return 301 https://$host$request_uri;
}
EOF

ln -s /etc/nginx/sites-available/network-analyzer /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx
```

Then open port 443 in NSG.

> **Note:** Currently port 8080 is NOT open in the NSG (SSH tunnel only). If you add Nginx with HTTPS, you'd need to add an NSG rule for port 443 on both the VM and subnet NSGs. Consider keeping SSH tunnel for small teams and only adding Nginx/HTTPS for larger rollouts.

---

## Add Authentication (Basic Auth via Nginx)

Quick option before Azure AD:

```bash
apt install -y apache2-utils
htpasswd -c /etc/nginx/.htpasswd analyst

# Add to nginx location block:
# auth_basic "Network Analyzer";
# auth_basic_user_file /etc/nginx/.htpasswd;
```

---

## Use a Larger LLM Model

For better analysis quality:

```bash
# Requires more VRAM
ollama pull llama3.1:70b    # 70B params, ~40 GB — needs 4x T4 or 1x A100

# Or a good middle ground
ollama pull llama3.1        # Current 8B — best for single T4
```

Update the service environment:
```bash
sed -i 's/OLLAMA_MODEL=llama3.1/OLLAMA_MODEL=llama3.1:70b/' /etc/systemd/system/network-analyzer.service
systemctl daemon-reload
systemctl restart network-analyzer
```

---

## Azure Application Gateway (Multi-VM HA)

For 50+ users with high availability:

```powershell
# Create Application Gateway
az network application-gateway create `
  --resource-group $RG `
  --name "appgw-network-analyzer" `
  --sku Standard_v2 `
  --capacity 2 `
  --http-settings-port 8080 `
  --http-settings-protocol Http `
  --frontend-port 443

# Add backend VMs
az network application-gateway address-pool update `
  --gateway-name "appgw-network-analyzer" `
  --resource-group $RG `
  --name appGatewayBackendPool `
  --servers <VM1-IP> <VM2-IP>
```

---

## Production Checklist

- [x] Switch from direct access to SSH tunnel
- [x] Remove all public web ports from NSG
- [x] Session history persistence (JSON files on disk)
- [x] New Session button for easy workflow reset
- [ ] Switch from Flask dev server to Gunicorn
- [ ] Add HTTPS via Nginx or Application Gateway (for large team rollout)
- [ ] Restrict SSH NSG rules to corporate IP ranges
- [ ] Add authentication (Azure AD or Basic Auth)
- [ ] Switch from Spot to Regular VM priority
- [ ] Set up monitoring (Azure Monitor / alerts)
- [x] Configure auto-start on VM reboot (systemd enabled)
- [ ] Back up the Python source to git repo
- [ ] Document runbook for on-call team
