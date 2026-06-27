COMPOSE_DEV=docker compose
COMPOSE_STAGE=docker compose -f docker-compose.yml -f docker-compose.stage.yml
COMPOSE_PROD=docker compose -f docker-compose.yml -f docker-compose.prod.yml
COMPOSE_PROD_LLM=docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.llm.yml
RUST_BACKEND_MANIFEST=rust/iscy-backend/Cargo.toml

.PHONY: dev-up dev-down stage-up stage-down prod-up prod-down prod-up-llm llm-download backup restore health local-bootstrap local-check local-test team-test docker-check docker-smoke easy-start prod-readiness rust-build rust-test rust-run rust-init rust-smoke rust-restore-smoke rust-postgres-restore-drill docs-pdf canary-daily rust-import-collection rust-sync-recent rust-canary-parity rust-canary-trend rust-canary-import

local-bootstrap: rust-init

local-check: rust-test

local-test: rust-test

team-test: rust-test rust-smoke rust-restore-smoke

docker-check:
	$(COMPOSE_DEV) config >/dev/null
	$(COMPOSE_STAGE) config >/dev/null
	$(COMPOSE_PROD) config >/dev/null
	$(COMPOSE_PROD_LLM) config >/dev/null

docker-smoke:
	$(COMPOSE_DEV) up -d db app
	$(COMPOSE_DEV) exec app wget -q -O /dev/null http://127.0.0.1:9000/health/live
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

docs-pdf:
	cargo run --manifest-path $(RUST_BACKEND_MANIFEST) --bin iscy-doc-pdf -- docs/ISCY_Handbuch.md docs/ISCY_Handbuch.pdf

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
	curl -fsS "$$url/status/operations.json" >/dev/null; \
	curl -fsS "$$url/metrics" >/dev/null; \
	curl -fsS -c "$$cookie_file" -H "content-type: application/json" -d '{"tenant_id":1,"username":"admin","password":"Admin123!"}' "$$url/api/v1/auth/sessions" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/api/v1/auth/session" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/dashboard/" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/admin/users/" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/imports/" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/incidents/" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/incidents/1" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/incidents/1/nis2-export" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/incidents/1/nis2-export.html" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/incidents/1/nis2-export.pdf" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/incidents/1/dora-export" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/incidents/1/dsgvo-export.html" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/api/v1/accounts/users" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/api/v1/accounts/roles" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/api/v1/accounts/groups" >/dev/null; \
	curl -fsS -b "$$cookie_file" "$$url/api/v1/accounts/permissions" >/dev/null; \
	curl -fsS -b "$$cookie_file" -F import_type='processes' -F "file=@$$import_file;filename=preview.csv;type=text/csv" "$$url/api/v1/import-center/preview" >/dev/null; \
	curl -fsS -b "$$cookie_file" -H "content-type: application/json" -d '{"import_type":"business_units","replace_existing":false,"csv_data":"name\nRust Smoke Import"}' "$$url/api/v1/import-center/csv" >/dev/null; \
	curl -fsS -b "$$cookie_file" -F title='Rust Smoke Evidence' -F status='SUBMITTED' -F session_id='1' -F requirement_id='1' -F incident_id='1' -F "file=@$$evidence_file;filename=evidence.txt;type=text/plain" "$$url/api/v1/evidence/uploads" >/dev/null; \
	curl -fsS "$$url/dashboard/?tenant_id=1&user_id=1" >/dev/null; \
	curl -fsS -H "x-iscy-tenant-id: 1" -H "x-iscy-user-id: 1" "$$url/api/v1/catalog/domains" >/dev/null; \
	curl -fsS -H "x-iscy-tenant-id: 1" -H "x-iscy-user-id: 1" "$$url/api/v1/requirements" >/dev/null; \
	curl -fsS -H "x-iscy-tenant-id: 1" -H "x-iscy-user-id: 1" "$$url/api/v1/incidents" >/dev/null; \
	curl -fsS -H "x-iscy-tenant-id: 1" -H "x-iscy-user-id: 1" "$$url/api/v1/incidents/1/nis2-export" >/dev/null; \
	curl -fsS -H "x-iscy-tenant-id: 1" -H "x-iscy-user-id: 1" "$$url/api/v1/incidents/1/nis2-export.html" >/dev/null; \
	curl -fsS -H "x-iscy-tenant-id: 1" -H "x-iscy-user-id: 1" "$$url/api/v1/incidents/1/nis2-export.pdf" >/dev/null; \
	curl -fsS -H "x-iscy-tenant-id: 1" -H "x-iscy-user-id: 1" "$$url/api/v1/incidents/1/dora-export" >/dev/null; \
	curl -fsS -H "x-iscy-tenant-id: 1" -H "x-iscy-user-id: 1" "$$url/api/v1/incidents/1/dsgvo-export.pdf" >/dev/null; \
	curl -fsS -H "x-iscy-tenant-id: 1" -H "x-iscy-user-id: 1" "$$url/api/v1/product-security/overview" >/dev/null; \
	curl -fsS -H "x-iscy-tenant-id: 1" -H "x-iscy-user-id: 1" "$$url/api/v1/status/metrics?tenant_id=1&user_id=1" >/dev/null; \
	echo "Rust smoke OK: $$url"

rust-restore-smoke:
	@tmpdir=$$(mktemp -d); \
	db_path="$$tmpdir/iscy-source.sqlite3"; \
	restore_path="$$tmpdir/iscy-restored.sqlite3"; \
	db_url="sqlite:////$${db_path#/}"; \
	restore_url="sqlite:////$${restore_path#/}"; \
	media_dir="$$tmpdir/media"; \
	restore_media="$$tmpdir/restored-media"; \
	cookie_file="$$tmpdir/iscy-restore.cookies"; \
	evidence_file="$$tmpdir/restore-evidence.txt"; \
	bind="$${RUST_RESTORE_BIND:-127.0.0.1:19001}"; \
	host="$${bind%:*}"; \
	port="$${bind##*:}"; \
	if [ "$$host" = "0.0.0.0" ]; then host="127.0.0.1"; fi; \
	url="http://$$host:$$port"; \
	command -v jq >/dev/null; \
	printf 'restore smoke evidence\n' > "$$evidence_file"; \
	echo "Rust restore smoke source DB: $$db_url"; \
	DATABASE_URL="$$db_url" cargo run --manifest-path $(RUST_BACKEND_MANIFEST) --bin iscy-backend -- init-demo; \
	DATABASE_URL="$$db_url" ISCY_MEDIA_ROOT="$$media_dir" RUST_BACKEND_BIND="$$bind" cargo run --manifest-path $(RUST_BACKEND_MANIFEST) --bin iscy-backend >"$$tmpdir/iscy-source.log" 2>&1 & \
	pid="$$!"; \
	trap 'kill "$$pid" >/dev/null 2>&1 || true' EXIT INT TERM; \
	for _ in $$(seq 1 60); do \
		if curl -fsS "$$url/health/live" >/dev/null 2>&1; then break; fi; \
		if ! kill -0 "$$pid" >/dev/null 2>&1; then cat "$$tmpdir/iscy-source.log"; exit 1; fi; \
		sleep 1; \
	done; \
	curl -fsS "$$url/health/live" >/dev/null; \
	curl -fsS -c "$$cookie_file" -H "content-type: application/json" -d '{"tenant_id":1,"username":"admin","password":"Admin123!"}' "$$url/api/v1/auth/sessions" >/dev/null; \
	upload_json=$$(curl -fsS -b "$$cookie_file" -F title='Restore Integrity Probe' -F status='SUBMITTED' -F "file=@$$evidence_file;filename=restore-evidence.txt;type=text/plain" "$$url/api/v1/evidence/uploads"); \
	relative_file=$$(printf '%s' "$$upload_json" | jq -er '.item.file_name'); \
	source_hash=$$(sha256sum "$$media_dir/$$relative_file" | cut -d ' ' -f 1); \
	kill "$$pid" >/dev/null 2>&1 || true; \
	wait "$$pid" 2>/dev/null || true; \
	pid=""; \
	cp "$$db_path" "$$restore_path"; \
	cp -a "$$media_dir" "$$restore_media"; \
	DATABASE_URL="$$restore_url" cargo run --manifest-path $(RUST_BACKEND_MANIFEST) --bin iscy-backend -- migrate; \
	test -s "$$restore_path"; \
	restored_file=$$(sqlite3 "$$restore_path" "SELECT file FROM evidence_evidenceitem WHERE tenant_id = 1 AND title = 'Restore Integrity Probe' ORDER BY id DESC LIMIT 1;"); \
	test "$$restored_file" = "$$relative_file"; \
	test -f "$$restore_media/$$restored_file"; \
	restored_hash=$$(sha256sum "$$restore_media/$$restored_file" | cut -d ' ' -f 1); \
	test "$$restored_hash" = "$$source_hash"; \
	echo "Rust restore smoke OK: $$restore_url"

rust-postgres-restore-drill:
	@if [ -z "$$ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL" ] || [ -z "$$ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL" ]; then \
		echo "Rust PostgreSQL restore drill SKIP: set ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL and ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL for disposable test databases."; \
		exit 0; \
	fi; \
	command -v pg_dump >/dev/null; \
	command -v pg_restore >/dev/null; \
	command -v psql >/dev/null; \
	tmpdir=$$(mktemp -d); \
	dump_file="$$tmpdir/iscy-postgres.dump"; \
	source_url="$$ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL"; \
	restore_url="$$ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL"; \
	echo "Rust PostgreSQL restore drill source: $$source_url"; \
	DATABASE_URL="$$source_url" cargo run --manifest-path $(RUST_BACKEND_MANIFEST) --bin iscy-backend -- init-demo; \
	pg_dump --format=custom --no-owner --no-privileges --dbname="$$source_url" --file="$$dump_file"; \
	psql "$$restore_url" -v ON_ERROR_STOP=1 -c 'DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;' >/dev/null; \
	pg_restore --dbname="$$restore_url" --no-owner --no-privileges "$$dump_file"; \
	DATABASE_URL="$$restore_url" cargo run --manifest-path $(RUST_BACKEND_MANIFEST) --bin iscy-backend -- migrate; \
	psql "$$restore_url" -v ON_ERROR_STOP=1 -c 'SELECT COUNT(*) FROM iscy_schema_migrations;' >/dev/null; \
	echo "Rust PostgreSQL restore drill OK"

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
	curl -fsS http://127.0.0.1:9000/health/ready
