#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

info() { printf '\033[1;34m[INFO]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$1"; }
err()  { printf '\033[1;31m[ERR ]\033[0m %s\n' "$1" >&2; }

if [ ! -d ".venv" ]; then
  info "Erstelle virtuelle Umgebung (.venv) mit --copies ..."
  python3 -m venv --copies .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
python -c "import sys, encodings; print('Python OK:', sys.executable)" >/dev/null

AUTO_YES="${AUTO_YES:-0}"
INSTALL_LOCAL_LLM="${INSTALL_LOCAL_LLM:-0}"
DOWNLOAD_LOCAL_LLM="${DOWNLOAD_LOCAL_LLM:-0}"
VERIFY_LOCAL_LLM="${VERIFY_LOCAL_LLM:-0}"
LOCAL_LLM_TARGET_DIR="${LOCAL_LLM_TARGET_DIR:-models}"
LOCAL_LLM_HF_REPO_ID="${LOCAL_LLM_HF_REPO_ID:-MaziyarPanahi/Qwen3-8B-GGUF}"
LOCAL_LLM_HF_FILENAME="${LOCAL_LLM_HF_FILENAME:-Qwen3-8B.Q4_K_M.gguf}"
LOCAL_LLM_MODEL_PATH="${LOCAL_LLM_MODEL_PATH:-}"

if [ -z "$LOCAL_LLM_MODEL_PATH" ]; then
  LOCAL_LLM_MODEL_PATH="$PROJECT_DIR/$LOCAL_LLM_TARGET_DIR/$LOCAL_LLM_HF_FILENAME"
fi

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  cp .env.example .env
  info ".env aus .env.example erstellt."
fi

set_env_var() {
  local key="$1" value="$2"
  python - "$key" "$value" <<'PY'
import sys
from pathlib import Path
key = sys.argv[1]
value = sys.argv[2]
p = Path('.env')
lines = p.read_text().splitlines() if p.exists() else []
out = []
found = False
for line in lines:
    if line.startswith(f"{key}="):
        out.append(f"{key}={value}")
        found = True
    else:
        out.append(line)
if not found:
    out.append(f"{key}={value}")
p.write_text("\n".join(out) + "\n")
PY
}

python_has_module() {
  local module="$1"
  python - "$module" <<'PY' >/dev/null 2>&1
import importlib, sys
module = sys.argv[1]
importlib.import_module(module)
PY
}

install_system_packages_for_llm() {
  if ! command -v sudo >/dev/null 2>&1; then
    err "sudo wurde nicht gefunden. Bitte installiere clang, openblas und g++-14 manuell."
    exit 1
  fi
  info "Installiere/prüfe Systempakete für lokalen llama-cpp-python-Build ..."
  sudo apt update
  sudo apt install -y build-essential cmake ninja-build pkg-config python3-dev clang libopenblas-dev g++-14 libstdc++-14-dev
}

install_llm_runtime() {
  info "Installiere Python-Abhängigkeiten für lokalen LLM-Betrieb ..."
  python -m pip install --upgrade pip setuptools wheel
  pip install huggingface_hub>=0.34.0

  if python_has_module llama_cpp; then
    info "llama-cpp-python ist bereits importierbar."
    return 0
  fi

  install_system_packages_for_llm

  unset CC CXX CMAKE_ARGS FORCE_CMAKE PIP_NO_BINARY PIP_ONLY_BINARY
  export CC=/usr/bin/clang
  export CXX=/usr/bin/clang++
  export CMAKE_ARGS="-DGGML_BLAS=ON -DGGML_BLAS_VENDOR=OpenBLAS -DLLAMA_BUILD_TOOLS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_SERVER=OFF"
  export FORCE_CMAKE=1

  info "Baue llama-cpp-python lokal mit clang + OpenBLAS ..."
  pip uninstall -y llama-cpp-python >/dev/null 2>&1 || true
  pip install --no-cache-dir --force-reinstall --no-binary=llama-cpp-python llama-cpp-python

  if ! python_has_module llama_cpp; then
    err "llama-cpp-python konnte nach dem Build nicht importiert werden."
    exit 1
  fi
  info "llama-cpp-python Runtime ist bereit."
}

mkdir -p static media "$LOCAL_LLM_TARGET_DIR"

info "Aktualisiere pip ..."
python -m pip install --upgrade pip

info "Installiere Basis-Abhängigkeiten ..."
pip install -r requirements.txt

if [ ! -f "$LOCAL_LLM_MODEL_PATH" ] && [ "$AUTO_YES" = "1" ]; then
  DOWNLOAD_LOCAL_LLM=1
  INSTALL_LOCAL_LLM=1
fi

if [ "$AUTO_YES" != "1" ] && [ -t 0 ] && [ ! -f "$LOCAL_LLM_MODEL_PATH" ]; then
  printf "\nLokales LLM-Modell gefunden? %s\n" "$LOCAL_LLM_MODEL_PATH"
  read -r -p "Qwen3-8B Q4_K_M GGUF jetzt herunterladen und konfigurieren? [y/N] " reply || true
  case "$reply" in
    [Yy]* )
      DOWNLOAD_LOCAL_LLM=1
      INSTALL_LOCAL_LLM=1
      ;;
  esac
fi

if [ "$INSTALL_LOCAL_LLM" = "1" ] || [ "$DOWNLOAD_LOCAL_LLM" = "1" ] || [ "$VERIFY_LOCAL_LLM" = "1" ]; then
  install_llm_runtime
fi

if [ "$DOWNLOAD_LOCAL_LLM" = "1" ]; then
  info "Bereite Modell-Download vor ..."
  pip install -r requirements-llm.txt
  python scripts/download_local_llm.py \
    --repo-id "$LOCAL_LLM_HF_REPO_ID" \
    --filename "$LOCAL_LLM_HF_FILENAME" \
    --target-dir "$LOCAL_LLM_TARGET_DIR"
fi

if [ -f "$LOCAL_LLM_MODEL_PATH" ]; then
  info "Lokales Modell gefunden: $LOCAL_LLM_MODEL_PATH"
  set_env_var "LOCAL_LLM_ENABLED" "True"
  set_env_var "LOCAL_LLM_BACKEND" "llama_cpp"
  set_env_var "LOCAL_LLM_MODEL_NAME" "Qwen3-8B-GGUF"
  set_env_var "LOCAL_LLM_MODEL_PATH" "$LOCAL_LLM_MODEL_PATH"
  set_env_var "LOCAL_LLM_HF_REPO_ID" "$LOCAL_LLM_HF_REPO_ID"
  set_env_var "LOCAL_LLM_HF_FILENAME" "$LOCAL_LLM_HF_FILENAME"
  set_env_var "LOCAL_LLM_TARGET_DIR" "$LOCAL_LLM_TARGET_DIR"
  set_env_var "LOCAL_LLM_VERBOSE_NATIVE" "False"
else
  warn "Kein lokales GGUF-Modell gefunden. Die App startet ohne LLM-Enrichment."
  set_env_var "LOCAL_LLM_ENABLED" "False"
fi

info "Führe Migrationen und Seeds aus ..."
python manage.py makemigrations
python manage.py migrate
python manage.py seed_demo || true
python manage.py seed_catalog || true
python manage.py seed_requirements || true
python manage.py seed_product_security || true

if [ "$VERIFY_LOCAL_LLM" = "1" ] && [ -f "$LOCAL_LLM_MODEL_PATH" ]; then
  info "Prüfe lokales LLM per Django-Command ..."
  python manage.py check_local_llm --generate || {
    err "LLM-Selbsttest fehlgeschlagen. Starte App nicht automatisch."
    exit 1
  }
fi

info "Prüfe Django-Konfiguration ..."
python manage.py check

info "Starte Django-Server ..."
python manage.py runserver
