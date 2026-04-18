COMPOSE_DEV=docker compose
COMPOSE_STAGE=docker compose -f docker-compose.yml -f docker-compose.stage.yml
COMPOSE_PROD=docker compose -f docker-compose.yml -f docker-compose.prod.yml
COMPOSE_PROD_LLM=docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.llm.yml
PYTHON_BIN=$(shell if [ -x .venv/bin/python ]; then echo .venv/bin/python; else echo python; fi)
TEAM_TEST_ENV=GUIDANCE_SCORING_BACKEND=local RISK_SCORING_BACKEND=local REPORT_SUMMARY_BACKEND=local REPORT_SNAPSHOT_BACKEND=local DASHBOARD_SUMMARY_BACKEND=local ASSET_INVENTORY_BACKEND=local PROCESS_REGISTER_BACKEND=local RISK_REGISTER_BACKEND=local EVIDENCE_REGISTER_BACKEND=local ASSESSMENT_REGISTER_BACKEND=local RUST_BACKEND_URL=

.PHONY: dev-up dev-down stage-up stage-down prod-up prod-down prod-up-llm llm-download backup restore health handbook-pdf local-bootstrap local-check local-test team-test docker-check docker-smoke easy-start prod-readiness rust-build rust-test rust-run canary-daily rust-import-collection rust-sync-recent rust-canary-parity rust-canary-trend rust-canary-import

local-bootstrap:
	python3 -m venv .venv
	mkdir -p static media staticfiles models
	. .venv/bin/activate && python -m ensurepip --upgrade && python -m pip install --upgrade pip setuptools wheel && python -m pip install -r requirements.txt

local-check:
	. .venv/bin/activate && python manage.py check

local-test:
	. .venv/bin/activate && python manage.py test apps.core apps.reports apps.product_security

team-test:
	$(TEAM_TEST_ENV) $(PYTHON_BIN) manage.py check
	$(TEAM_TEST_ENV) $(PYTHON_BIN) manage.py test apps.core apps.reports apps.product_security apps.guidance apps.dashboard apps.assets_app apps.processes apps.risks apps.evidence apps.assessments apps.vulnerability_intelligence

docker-check:
	$(COMPOSE_DEV) config >/dev/null
	$(COMPOSE_STAGE) config >/dev/null
	$(COMPOSE_PROD) config >/dev/null
	$(COMPOSE_PROD_LLM) config >/dev/null

docker-smoke:
	$(COMPOSE_DEV) up -d db
	$(COMPOSE_DEV) run --rm web python manage.py migrate
	$(COMPOSE_DEV) run --rm web python manage.py check
	$(COMPOSE_DEV) down

easy-start:
	./scripts/easy_start.sh

prod-readiness:
	./scripts/production_readiness_check.sh

rust-build:
	cargo build --manifest-path rust/iscy-backend/Cargo.toml

rust-test:
	cargo test --manifest-path rust/iscy-backend/Cargo.toml

rust-run:
	cargo run --manifest-path rust/iscy-backend/Cargo.toml

canary-daily:
	./scripts/run_daily_canary.sh

rust-import-collection:
	cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-canary -- import-collection $(ARGS)

rust-sync-recent:
	cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-canary -- sync-recent $(ARGS)

rust-canary-import:
	cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-canary -- import $(ARGS)

rust-canary-parity:
	cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-canary -- parity $(ARGS)

rust-canary-trend:
	cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-canary -- trend $(ARGS)

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
	@echo "Rust-LLM-Setup benötigt keinen separaten Modell-Download-Container."

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
