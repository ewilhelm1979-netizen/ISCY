#!/usr/bin/env bash
set -euo pipefail

unset ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL
unset ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL

exec make postgresql-18-compatibility
