# ISCY auf Proxmox produktiv betreiben (VM + Docker Compose)

Dieses Runbook beschreibt den empfohlenen Betriebsweg:

- Proxmox VM (Debian/Ubuntu LTS)
- Docker + Compose in der VM
- ISCY via `docker-compose.prod.yml` (optional mit `docker-compose.llm.yml`)

## 1. Zielbild

- Proxmox stellt Virtualisierung, Snapshot und Backup bereit.
- Die VM kapselt OS-Hardening und Host-Patches.
- Docker Compose kapselt App, DB und Reverse Proxy.

## 2. VM-Baseline (Empfehlung)

- 4 vCPU, 8-16 GB RAM, 80+ GB SSD
- Ubuntu 24.04 LTS oder Debian 12
- feste IP / DNS
- Zeitsync (NTP), Host-Firewall aktiv

## 3. Installation in der VM

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git docker.io docker-compose-plugin
sudo systemctl enable --now docker
git clone <repo-url> /opt/iscy
cd /opt/iscy
cp .env.production.example .env
```

Danach `.env` produktiv setzen (mind. `SECRET_KEY`, `DEBUG=False`, `ALLOWED_HOSTS`, DB-Creds).

## 4. Produktionsstart

```bash
make prod-readiness
make prod-up
```

Mit lokalem LLM:

```bash
make llm-download
make prod-up-llm
```

## 5. Nach dem Start pruefen

- `docker compose -f docker-compose.yml -f docker-compose.prod.yml ps`
- `curl -f http://127.0.0.1/health/live/`
- `curl -f http://127.0.0.1/health/ready/`

## 6. Backup / Restore

Backup:

```bash
ENV_FILE=.env.production ./scripts/backup_compose.sh
```

Restore-Test (mind. monatlich):

```bash
ENV_FILE=.env.production ./scripts/restore_compose.sh backups/<timestamp>
```

## 7. Betriebsvorgaben

- Security-Updates fuer VM monatlich
- Docker-Image-Updates kontrolliert in Stage testen
- `make team-test` vor Rollout
- Restore-Drill regelmaessig dokumentieren
- NVD-Sync als geplanter Job (`sync_nvd_recent`)
