# 02 — Full VM Setup from Scratch

> Deploy a brand-new Azure GPU VM with Ollama + Network Analyzer from zero.

## Prerequisites

- Azure CLI installed and authenticated (`az login`)
- Subscription with GPU VM quota (NC-series)
- Source code at: `src/network_analyzer.py`

## Step 1: Set Variables

```powershell
$RG = "rg-network-analyzer-prod"          # Resource group name
$LOCATION = "southcentralus"               # Azure region
$VM_NAME = "vm-network-analyzer"           # VM name
$VM_SIZE = "Standard_NC4as_T4_v3"          # GPU VM size (see 09_COST_BUDGET.md)
$ADMIN_USER = "azureuser"                  # SSH username
$VNET_NAME = "vnet-network-analyzer"       # VNet name
$SUBNET_NAME = "snet-app"                  # Subnet name
$NSG_NAME = "$VM_NAME-nsg"                 # NSG name
$DATA_DISK_SIZE = 256                      # Data disk in GB
```

## Step 2: Create Resource Group

```powershell
az group create --name $RG --location $LOCATION
```

## Step 3: Create Networking

```powershell
# VNet + Subnet
az network vnet create `
  --resource-group $RG --name $VNET_NAME `
  --address-prefix 10.0.0.0/16 `
  --subnet-name $SUBNET_NAME --subnet-prefix 10.0.0.0/24

# NSG
az network nsg create --resource-group $RG --name $NSG_NAME

# SSH rule (the ONLY inbound rule needed — all web access goes through SSH tunnel)
az network nsg rule create `
  --resource-group $RG --nsg-name $NSG_NAME `
  --name Allow-SSH --priority 100 --direction Inbound --access Allow `
  --protocol Tcp --destination-port-ranges 22 --source-address-prefixes "*"

# Public IP
az network public-ip create `
  --resource-group $RG --name "$VM_NAME-pip" `
  --sku Standard --allocation-method Static

# NIC
az network nic create `
  --resource-group $RG --name "$VM_NAME-nic" `
  --vnet-name $VNET_NAME --subnet $SUBNET_NAME `
  --network-security-group $NSG_NAME --public-ip-address "$VM_NAME-pip"
```

## Step 4: Create the VM

```powershell
az vm create `
  --resource-group $RG --name $VM_NAME `
  --size $VM_SIZE --image Ubuntu2404 `
  --admin-username $ADMIN_USER --generate-ssh-keys `
  --nics "$VM_NAME-nic" `
  --os-disk-size-gb 64 --data-disk-sizes-gb $DATA_DISK_SIZE `
  --priority Regular

# Get Public IP
$VM_IP = az vm show --resource-group $RG --name $VM_NAME --show-details --query publicIps -o tsv
Write-Host "VM IP: $VM_IP"
```

> **For Spot pricing** (dev/test only), add `--priority Spot --eviction-policy Deallocate --max-price -1`

## Step 5: Install NVIDIA GPU Drivers

```powershell
az vm run-command invoke --resource-group $RG --name $VM_NAME --command-id RunShellScript --scripts "
apt-get update
apt-get install -y ubuntu-drivers-common
ubuntu-drivers install
"

# Reboot to load drivers
az vm restart --resource-group $RG --name $VM_NAME

# Wait 2 minutes, then verify GPU
az vm run-command invoke --resource-group $RG --name $VM_NAME --command-id RunShellScript --scripts "nvidia-smi"
```

Expected output: `Tesla T4, 16384 MiB`

## Step 6: Mount Data Disk

```powershell
az vm run-command invoke --resource-group $RG --name $VM_NAME --command-id RunShellScript --scripts "
DISK=`$(lsblk -d -n -o NAME,SIZE | grep -v sda | grep -v sdb | tail -1 | awk '{print `$1}')
mkfs.ext4 /dev/`$DISK
mkdir -p /data
mount /dev/`$DISK /data
echo '/dev/'`$DISK' /data ext4 defaults 0 2' >> /etc/fstab
mkdir -p /data/network-analyzer
df -h /data
"
```

## Step 7: Install Ollama

See [03_OLLAMA_SETUP.md](03_OLLAMA_SETUP.md) for full details.

```powershell
az vm run-command invoke --resource-group $RG --name $VM_NAME --command-id RunShellScript --scripts "
curl -fsSL https://ollama.com/install.sh | sh
systemctl enable ollama
systemctl start ollama
sleep 10
ollama pull llama3.1
ollama list
"
```

## Step 8: Install Python Dependencies

```powershell
az vm run-command invoke --resource-group $RG --name $VM_NAME --command-id RunShellScript --scripts "
pip3 install flask scapy haralyzer requests --break-system-packages
pip3 list | grep -iE 'flask|scapy|haral|requests'
"
```

## Step 9: Deploy the Application

See [04_APP_DEPLOYMENT.md](04_APP_DEPLOYMENT.md) for full details.

```powershell
$content = Get-Content -Path "src/network_analyzer.py" -Raw -Encoding UTF8
$bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
$b64 = [Convert]::ToBase64String($bytes)
$script = "echo '$b64' | base64 -d > /data/network-analyzer/network_analyzer.py && wc -l /data/network-analyzer/network_analyzer.py"
Set-Content -Path "deploy.sh" -Value $script -Encoding ASCII
az vm run-command invoke --resource-group $RG --name $VM_NAME --command-id RunShellScript --scripts @deploy.sh
```

## Step 10: Create Systemd Service

```powershell
az vm run-command invoke --resource-group $RG --name $VM_NAME --command-id RunShellScript --scripts "
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
sleep 2
systemctl status network-analyzer --no-pager
"
```

## Step 11: Set Up SSH Keys for Tunnel Access

```powershell
# Generate an SSH key pair (if you don't already have one)
ssh-keygen -t rsa -b 4096 -f "$env:USERPROFILE\.ssh\id_rsa" -N '""'

# Push the public key to the VM
$PUBKEY = Get-Content "$env:USERPROFILE\.ssh\id_rsa.pub" -Raw
az vm run-command invoke --resource-group $RG --name $VM_NAME --command-id RunShellScript --scripts "
mkdir -p /home/$ADMIN_USER/.ssh
echo '$PUBKEY' >> /home/$ADMIN_USER/.ssh/authorized_keys
chmod 700 /home/$ADMIN_USER/.ssh
chmod 600 /home/$ADMIN_USER/.ssh/authorized_keys
chown -R ${ADMIN_USER}:${ADMIN_USER} /home/$ADMIN_USER/.ssh
"
```

## Step 12: Verify via SSH Tunnel

```powershell
# Start SSH tunnel (keep this terminal open)
az ssh vm --resource-group $RG --name $VM_NAME --local-user $ADMIN_USER -- -L 8080:localhost:8080 -N

# In another terminal, test:
$r = Invoke-WebRequest -Uri "http://localhost:8080" -TimeoutSec 10 -UseBasicParsing
Write-Host "HTTP $($r.StatusCode), $($r.Content.Length) bytes"

# Open in browser
Start-Process "http://localhost:8080"
```

> **Important:** Port 8080 is NOT open in the NSG. All access goes through the SSH tunnel.
> The `az ssh vm` command works even on VPN — it routes through the Azure control plane.

## Total Time: ~30-45 minutes
