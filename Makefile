COMPOSE_DEV=docker compose
COMPOSE_STAGE=docker compose -f docker-compose.yml -f docker-compose.stage.yml
COMPOSE_PROD=docker compose -f docker-compose.yml -f docker-compose.prod.yml
COMPOSE_PROD_LLM=docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.llm.yml

.PHONY: dev-up dev-down stage-up stage-down prod-up prod-down prod-up-llm llm-download backup restore health handbook-pdf

dev-up:
	$(COMPOSE_DEV) up --build

dev-down:
	$(COMPOSE_DEV) down

stage-up:
	$(COMPOSE_STAGE) up --build -d

stage-down:
	$(COMPOSE_STAGE) down

prod-up:
	$(COMPOSE_PROD) up --build -d

prod-down:
	$(COMPOSE_PROD) down

prod-up-llm:
	$(COMPOSE_PROD_LLM) up --build -d

llm-download:
	$(COMPOSE_PROD_LLM) run --rm --profile llm-setup model-downloader

backup:
	ENV_FILE=.env.production ./scripts/backup_compose.sh

restore:
	@echo "Usage: make restore BACKUP=backups/<timestamp>"
	@test -n "$(BACKUP)"
	ENV_FILE=.env.production ./scripts/restore_compose.sh $(BACKUP)

health:
	curl -fsS http://127.0.0.1/health/ready/

handbook-pdf:
	python3 scripts/export_iscy_handbook_pdf.py
