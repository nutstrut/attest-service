#!/usr/bin/env bash
cd /home/ubuntu/attest-service
exec /home/ubuntu/.local/bin/uvicorn attest_service:app --host 0.0.0.0 --port 3004
