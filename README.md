# attest-service

Single-call verification for agent execution integrity. Accepts a single request,
runs pre-execution continuity evaluation and post-execution settlement verification
in sequence, and returns both signed receipts with a cryptographic chain binding.

Part of the DefaultVerifier infrastructure alongside
settlement-witness and continuity-analyzer.

## Endpoint

POST /v1/attest

Returns:
- Continuity receipt (pre-execution classification)
- SAR receipt (post-execution verdict)
- Chain binding (cryptographic linkage of both receipts)

## Quick Start

```bash
curl -X POST https://defaultverifier.com/v1/attest \
  -H "Content-Type: application/json" \
  --data @v1-attest-pass-test.json
```

See v1-attest-pass-test.json for a working request payload.

## Architecture

```text
attest-service (:3004)
  → continuity-analyzer (:3002)
  → settlement-witness (:3001)
```

## Deployment

Systemd:

cp attest-service.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable attest-service
systemctl start attest-service

Nginx:

location /v1/attest {
    proxy_pass http://127.0.0.1:3004;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

## Example Payloads

- `v1-attest-pass-test.json` — all continuity predicates pass, SAR returns PASS
- `v1-attest-partial-fail-test.json` — executor_continuity fails, SAR returns FAIL

