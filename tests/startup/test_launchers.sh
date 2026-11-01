#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "$0")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/scripts" "$fixture/bin"
cp "$project_dir/start.sh" "$fixture/start.sh"
cp "$project_dir/scripts/easy_start.sh" "$fixture/scripts/easy_start.sh"
printf 'DATABASE_URL=postgres://private-example\n' > "$fixture/.env.example"
export CALLS="$fixture/calls"
export ISCY_BACKEND_BIN="$fixture/bin/backend"
cat > "$ISCY_BACKEND_BIN" <<'MOCK'
#!/usr/bin/env bash
printf 'backend:%s\n' "$*" >> "$CALLS"
MOCK
cat > "$fixture/bin/make" <<'MOCK'
#!/usr/bin/env bash
printf 'make:%s\n' "$*" >> "$CALLS"
if [[ "$*" == docker-check ]]; then exit "${CHECK_EXIT:-0}"; fi
MOCK
chmod +x "$fixture/bin/"*
export PATH="$fixture/bin:$PATH"
cd "$fixture"
for args in '--help' 'check' 'doctor'; do
  ./start.sh "$args" > output
  [[ ! -e .env && ! -e "$CALLS" ]]
done
if ./start.sh --typo >output 2>&1; then exit 1; fi
if ./start.sh --help extra >output 2>&1; then exit 1; fi
[[ ! -e .env && ! -e "$CALLS" ]]
./start.sh run >output
[[ ! -e .env ]]
[[ "$(cat "$CALLS")" == 'backend:' ]]
rm "$CALLS"
./start.sh demo >output
[[ -f .env ]]
[[ "$(cat "$CALLS")" == $'backend:init-demo\nbackend:' ]]
if [[ "$(cat output)" == *private-example* ]]; then exit 1; fi
rm "$CALLS"
./scripts/easy_start.sh --native check >output
[[ ! -e "$CALLS" ]]
./scripts/easy_start.sh --compose check >output
[[ "$(cat "$CALLS")" == 'make:docker-check' ]]
rm "$CALLS"
if CHECK_EXIT=9 ./scripts/easy_start.sh --compose start >output 2>&1; then exit 1; fi
[[ "$(cat "$CALLS")" == 'make:docker-check' ]]
rm "$CALLS"
if ./scripts/easy_start.sh --compose --typo >output 2>&1; then exit 1; fi
[[ ! -e "$CALLS" ]]
./scripts/easy_start.sh --compose start >output
[[ "$(cat "$CALLS")" == $'make:docker-check\nmake:dev-up' ]]
printf 'Startup command and preflight contracts PASS\n'
