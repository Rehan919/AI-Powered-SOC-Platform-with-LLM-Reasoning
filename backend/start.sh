#!/bin/sh
set -e

echo "Waiting for postgres..."
while ! python -c "
import psycopg2
psycopg2.connect('$DATABASE_URL')
" 2>/dev/null; do
  sleep 1
done

echo "Postgres ready. Starting SentinelForge backend..."
exec uvicorn src.main:app --host 0.0.0.0 --port 8001
