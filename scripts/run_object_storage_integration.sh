#!/usr/bin/env bash
set -euo pipefail

MINIO_IMAGE="docker.io/minio/minio:RELEASE.2025-04-22T22-12-26Z"
MC_IMAGE="docker.io/minio/mc:RELEASE.2025-04-16T18-13-26Z"
CONTAINER_NAME="iscy-minio-integration-${RANDOM}-$$"
PORT="${ISCY_TEST_S3_PORT:-19090}"
BUCKET="iscy-integration-${RANDOM}-$$"
ACCESS_KEY="iscy_test_access" # gitleaks:allow
SECRET_KEY="iscy_test_secret_only_123456789" # gitleaks:allow

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run --detach --rm \
  --name "$CONTAINER_NAME" \
  --publish "127.0.0.1:${PORT}:9000" \
  --env "MINIO_ROOT_USER=${ACCESS_KEY}" \
  --env "MINIO_ROOT_PASSWORD=${SECRET_KEY}" \
  "$MINIO_IMAGE" server /data >/dev/null

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${PORT}/minio/health/ready" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${PORT}/minio/health/ready" >/dev/null

docker run --rm --network host \
  --env "MC_HOST_iscy=http://${ACCESS_KEY}:${SECRET_KEY}@127.0.0.1:${PORT}" \
  "$MC_IMAGE" mb --ignore-existing "iscy/${BUCKET}" >/dev/null

export ISCY_TEST_S3_ENDPOINT="http://127.0.0.1:${PORT}"
export ISCY_TEST_S3_BUCKET="$BUCKET"
export ISCY_EVIDENCE_OBJECT_STORAGE_ACCESS_KEY="$ACCESS_KEY"
export ISCY_EVIDENCE_OBJECT_STORAGE_SECRET_KEY="$SECRET_KEY"
export MINIO_TEST_SECRET_KEY="$SECRET_KEY"
cargo test --locked --manifest-path rust/iscy-backend/Cargo.toml \
  --test s3_runtime_integration -- --ignored --nocapture

docker run --rm --network host \
  --env "MC_HOST_iscy=http://${ACCESS_KEY}:${SECRET_KEY}@127.0.0.1:${PORT}" \
  "$MC_IMAGE" rb --force "iscy/${BUCKET}" >/dev/null

echo "Object storage integration OK"
