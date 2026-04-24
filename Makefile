COMPOSE_DEV=docker compose
COMPOSE_STAGE=docker compose -f docker-compose.yml -f docker-compose.stage.yml
COMPOSE_PROD=docker compose -f docker-compose.yml -f docker-compose.prod.yml
COMPOSE_PROD_LLM=docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.llm.yml
PYTHON_BIN=$(shell if [ -x .venv/bin/python ]; then echo .venv/bin/python; else echo python; fi)
TEAM_TEST_ENV=RUST_ONLY_MODE=False GUIDANCE_SCORING_BACKEND=local RISK_SCORING_BACKEND=local REPORT_SUMMARY_BACKEND=local REPORT_SNAPSHOT_BACKEND=local DASHBOARD_SUMMARY_BACKEND=local CATALOG_BACKEND=local REQUIREMENTS_BACKEND=local ASSET_INVENTORY_BACKEND=local PROCESS_REGISTER_BACKEND=local RISK_REGISTER_BACKEND=local EVIDENCE_REGISTER_BACKEND=local ASSESSMENT_REGISTER_BACKEND=local ROADMAP_REGISTER_BACKEND=local WIZARD_RESULTS_BACKEND=local IMPORT_CENTER_BACKEND=local PRODUCT_SECURITY_BACKEND=local RUST_BACKEND_URL=
RUST_BACKEND_MANIFEST=rust/iscy-backend/Cargo.toml

.PHONY: dev-up dev-down stage-up stage-down prod-up prod-down prod-up-llm llm-download backup restore health handbook-pdf local-bootstrap local-check local-test team-test docker-check docker-smoke easy-start prod-readiness rust-build rust-test rust-run rust-init rust-smoke canary-daily rust-import-collection rust-sync-recent rust-canary-parity rust-canary-trend rust-canary-import

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
	$(TEAM_TEST_ENV) $(PYTHON_BIN) manage.py test apps.core apps.reports apps.product_security apps.guidance apps.dashboard apps.catalog apps.requirements_app apps.assets_app apps.processes apps.risks apps.evidence apps.assessments apps.roadmap apps.wizard apps.import_center apps.vulnerability_intelligence

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
	cargo build --manifest-path $(RUST_BACKEND_MANIFEST)

rust-test:
	cargo test --manifest-path $(RUST_BACKEND_MANIFEST)

rust-run:
	cargo run --manifest-path $(RUST_BACKEND_MANIFEST) --bin iscy-backend

rust-init:
	cargo run --manifest-path $(RUST_BACKEND_MANIFEST) --bin iscy-backend -- init-demo

rust-smoke:
	@tmpdir=$$(mktemp -d); \
	db_path="$$tmpdir/iscy-smoke.sqlite3"; \
	db_url="sqlite:////$${db_path#/}"; \
	cookie_file="$$tmpdir/iscy-smoke.cookies"; \
	evidence_file="$$tmpdir/evidence.txt"; \
	import_file="$$tmpdir/import-preview.csv"; \
	bind="$${RUST_BACKEND_BIND:-127.0.0.1:19000}"; \
	host="$${bind%:*}"; \
	port="$${bind##*:}"; \
	if [ "$$host" = "0.0.0.0" ]; then host="127.0.0.1"; fi; \
	url="$${RUST_BACKEND_URL:-http://$$host:$$port}"; \
	printf 'rust smoke evidence\n' > "$$evidence_file"; \
	printf 'Name,Beschreibung,BusinessUnit,Status\nRust Smoke Process,Previewed import,Security Operations,PARTIAL\n' > "$$import_file"; \
	echo "Rust smoke DB: $$db_url"; \
	DATABASE_URL="$$db_url" cargo run --manifest-path $(RUST_BACKEND_MANIFEST) --bin iscy-backend -- init-demo; \
	DATABASE_URL="$$db_url" ISCY_MEDIA_ROOT="$$tmpdir/media" RUST_BACKEND_BIND="$$bind" cargo run --manifest-path $(RUST_BACKEND_MANIFEST) --bin iscy-backend >"$$tmpdir/iscy-backend.log" 2>&1 & \
	pid="$$!"; \
	trap 'kill "$$pid" >/dev/null 2>&1 || true' EXIT INT TERM; \
	for _ in $$(seq 1 60); do \
		if curl -fsS "$$url/health/live" >/dev/null 2>&1; then \
			break; \
		fi; \
		if ! kill -0 "$$pid" >/dev/null 2>&1; then \
			cat "$$tmpdir/iscy-backend.log"; \
			exit 1; \
		fi; \
		sleep 1; \
	done; \
	curl -fsS "$$url/health/live" >/dev/null; \
	curl -fsS -c "$$cookie_file" -H "content-type: application/json" -d '{"tenant_id":1,"username":"admin","password":"Admin123!"}' "$$url/api/v1/auth/sessions" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/api/v1/auth/session" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/dashboard/" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/admin/users/" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/imports/" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/api/v1/accounts/users" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/api/v1/accounts/roles" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/api/v1/accounts/groups" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/api/v1/accounts/permissions" >/dev/null; \
	curl -fsS -b "$$cookie_file" -F import_type='processes' -F "file=@$$import_file;filename=preview.csv;type=text/csv" "$$url/api/v1/import-center/preview" >/dev/null; \
	curl -fsS -b "$$cookie_file" -H "content-type: application/json" -d '{"import_type":"business_units","replace_existing":false,"csv_data":"name\nRust Smoke Import"}' "$$url/api/v1/import-center/csv" >/dev/null; \
	curl -fsS -b "$$cookie_file" -F title='Rust Smoke Evidence' -F status='SUBMITTED' -F session_id='1' -F requirement_id='1' -F "file=@$$evidence_file;filename=evidence.txt;type=text/plain" "$$url/api/v1/evidence/uploads" >/dev/null; \
	curl -fsS "$$url/dashboard/?tenant_id=1&user_id=1" >/dev/null; \
	curl -fsS -H "x-iscy-tenant-id: 1" -H "x-iscy-user-id: 1" "$$url/api/v1/catalog/domains" >/dev/null; \
	curl -fsS -H "x-iscy-tenant-id: 1" -H "x-iscy-user-id: 1" "$$url/api/v1/requirements" >/dev/null; \
	curl -fsS -H "x-iscy-tenant-id: 1" -H "x-iscy-user-id: 1" "$$url/api/v1/product-security/overview" >/dev/null; \
	echo "Rust smoke OK: $$url"

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
