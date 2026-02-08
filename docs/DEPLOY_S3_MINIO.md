
# S3/MinIO Publication (Receipts & Bundles)

This service can mirror canonical receipt bytes and offline bundles to S3-compatible storage.

## Env
- `S3_ENDPOINT`  (MinIO URL or empty for AWS)
- `S3_REGION`    (e.g., `us-east-1`)
- `S3_ACCESS_KEY`
- `S3_SECRET_KEY`
- `S3_BUCKET`    (e.g., `ubl-passports`)
- `S3_PUBLIC_BASE` (e.g., `https://cdn.ubl.agency`)

## Flow
1. Persist receipt row in Postgres (single-source-of-truth).
2. Upload canonical bytes to `receipts/{id}.json`.
3. Store the returned public URL in the `receipt.url` column.
4. Response returns **rich URL** and continues to include `cid|did|rt` for offline verification.
