#!/usr/bin/env bash
set -euo pipefail
# Fixed loopback fixture only. Ignore inherited connection services/options/credentials.
cd "$(dirname "$0")"
for attempt in 1 2; do
  env -i PATH="$PATH" PGHOST=127.0.0.1 PGPORT=5432 \
    PGDATABASE=task0_fixture PGUSER=fixture_admin \
    PGPASSWORD=disposable_fixture_only PGPASSFILE=/dev/null \
    PGSSLMODE=disable PGCONNECT_TIMEOUT=5 \
    psql -X --no-password --set=ON_ERROR_STOP=1 --file=postgres-fixture.sql
done
