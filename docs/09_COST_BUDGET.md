# 09 — Cost & Budget Planning

> Cost breakdown, Spot VM savings, scaling budgets.

## Current Cost (Dev/Prototype)

| Component | Pricing | Monthly Cost |
|---|---|---|
| **VM: NC4as_T4_v3** (Spot) | ~$0.073-0.22/hr (60-90% off) | **~$52 - $158** |
| **VM: NC4as_T4_v3** (Regular) | ~$0.73/hr | ~$526 |
| **OS Disk** (64 GB P6) | ~$4.80/mo | ~$5 |
| **Data Disk** (256 GB P15) | ~$28.80/mo | ~$29 |
| **Public IP** (Static Standard) | ~$3.65/mo | ~$4 |
| **Ollama + Model** | Free (open source) | $0 |
| **LLM API calls** | None (local inference) | $0 |

### Total Current Cost

| Mode | Monthly | Annual |
|---|---|---|
| **Spot VM** (current) | **~$90 - $196** | **~$1,080 - $2,352** |
| **Regular VM** | ~$564 | ~$6,768 |

> **We used Spot VMs to build this prototype within our limited budget.** Spot provided 60-90% savings on GPU compute, making it possible to develop and demonstrate without dedicated funding.

---

## Why We Used Spot VMs

**Pros:**
- 60-90% cost savings on GPU VMs
- Perfect for dev/test and prototyping
- Same hardware specs as regular VMs
- Can be started immediately when available

**Cons:**
- Azure can evict the VM at any time when capacity is needed
- Not suitable for always-on production services
- May need to restart manually after eviction
- Public IP may change if not using Static IP (we use Static)

**Our approach:** Use Spot for development and prototyping. Switch to Regular when approved for production rollout.

---

## Scaling Cost Projections

### Scenario A: Small Team (5-20 users)

| Component | Monthly |
|---|---|
| VM: NC8as_T4_v3 (Regular) | ~$752 |
| Disks + IP | ~$34 |
| Gunicorn (free) | $0 |
| **Total** | **~$786** |

### Scenario B: Medium Team (20-50 users)

| Component | Monthly |
|---|---|
| VM: NC16as_T4_v3 (Regular) | ~$1,204 |
| Disks + IP | ~$34 |
| Nginx + SSL cert | ~$0 (Let's Encrypt) |
| **Total** | **~$1,238** |

### Scenario C: Large Team (50-100+ users)

| Component | Monthly |
|---|---|
| VM: NC64as_T4_v4 (4 GPUs, Regular) | ~$4,816 |
| OR: 2x NC8as_T4_v3 + App Gateway | ~$1,504 + ~$200 |
| Disks + IP | ~$34-68 |
| App Gateway (Standard_v2) | ~$200 |
| **Total (single VM)** | **~$4,850** |
| **Total (multi-VM)** | **~$1,772** |

---

## Cost Comparison: Local LLM vs. Cloud API

| Approach | Per-Query Cost | 1000 queries/mo | Notes |
|---|---|---|---|
| **Our approach (local Ollama)** | $0.00 | **$0** (flat VM cost) | Unlimited queries |
| Azure OpenAI (GPT-4) | ~$0.03-0.10 | $30-$100 | Per-token billing |
| Azure OpenAI (GPT-4o) | ~$0.005-0.02 | $5-$20 | Per-token billing |
| OpenAI API (GPT-4) | ~$0.03-0.10 | $30-$100 | Data leaves Azure |

> **Key advantage:** With local Ollama, analysis queries are unlimited at flat VM cost. No per-token billing. No data leaves Azure.

---

## Budget Ask for Leadership

### Immediate Need (Production Pilot — 5-20 users)

| Item | Monthly | Annual |
|---|---|---|
| Regular GPU VM (NC4as_T4_v3 or NC8as_T4_v3) | $526-$752 | $6,312-$9,024 |
| Storage + networking | ~$34 | ~$408 |
| **Total** | **~$560-$786** | **~$6,720-$9,432** |

### Future Need (Full Rollout — 20-50 users)

| Item | Monthly | Annual |
|---|---|---|
| Larger VM (NC16as_T4_v3) | ~$1,204 | ~$14,448 |
| Storage + networking + SSL | ~$40 | ~$480 |
| **Total** | **~$1,244** | **~$14,928** |

---

## Cost Optimization Tips

1. **Deallocate VM after hours** — Stop the VM when not in use (no compute charges when deallocated)
   ```powershell
   az vm deallocate --resource-group $RG --name $VM  # Stop + free compute
   az vm start --resource-group $RG --name $VM       # Start when needed
   ```

2. **Reserved Instances** — 1-year commitment gives 30-40% savings
   ```
   NC4as_T4_v3: ~$526/mo regular → ~$368/mo reserved (1yr)
   ```

3. **Spot for dev/test** — Continue using Spot for development work

4. **Right-size the VM** — Monitor GPU utilization; don't over-provision

5. **Auto-shutdown schedule** — Azure VM auto-shutdown at end of business

---

## Subscription & Quota

Current subscription: `<YOUR-SUBSCRIPTION-ID>`

If you need more GPU VMs, check and request quota:
```powershell
az vm list-usage --location southcentralus -o table | Select-String "NC"
```

Request quota increase via Azure Portal → Subscriptions → Usage + quotas.
