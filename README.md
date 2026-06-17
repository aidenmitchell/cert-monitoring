# cert-monitoring

Capture the live Certificate Transparency (CT) feed and store it in ClickHouse so
you can **query certificates by domain** — exact (`mail.example.com`) and
subdomain/suffix (everything under `example.com`).

```
seed (one-shot) ─▶ ct_index.json
                       │
certstream-server-go ──ws(/lite)──▶ ingester (Python) ──batch INSERT──▶ ClickHouse
                                                                        certs ──MV──▶ domain_certs
```

- **seed** — one-shot job that writes each CT log's current tip to `ct_index.json` so certstream's recovery resumes from "now" instead of backfilling from 0. Idempotent; runs before certstream.
- **certstream-server-go** — streams parsed CT entries over WebSocket (lite stream, metadata only); `recovery` enabled so it resumes after a restart.
- **ingester** — Python (`websockets` + `clickhouse-connect`); parses each update, batches, inserts into `ct.certs`.
- **ClickHouse** — `ct.certs` (one row per cert) + `ct.domain_certs` (one row per domain, populated by a materialized view).

## Quick start

```bash
cp .env.example .env          # set CLICKHOUSE_PASSWORD
docker compose up -d --build
docker compose ps             # all three services up; clickhouse healthy
```

Schema is created automatically on first ClickHouse start from
`clickhouse/init/01-schema.sql`.

## Verify it's working

```bash
# Tables exist
docker compose exec clickhouse clickhouse-client --password "$CLICKHOUSE_PASSWORD" \
  -q "SHOW TABLES FROM ct"

# Rows climbing after ~30-60s of live traffic
docker compose exec clickhouse clickhouse-client --password "$CLICKHOUSE_PASSWORD" \
  -q "SELECT count() FROM ct.certs"
docker compose exec clickhouse clickhouse-client --password "$CLICKHOUSE_PASSWORD" \
  -q "SELECT count() FROM ct.domain_certs"   # larger — exploded by domain

# Ingester logs
docker compose logs -f ingester
```

## Querying by domain

See [`queries/examples.sql`](queries/examples.sql). The key idea: `domain_certs`
is sorted by a **reversed domain** (`www.example.com` → `com.example.www`), so all
subdomains of a parent share a literal prefix and suffix search becomes a
primary-key range scan.

```sql
-- all certs for example.com and any subdomain
SELECT domain, sha256, seen, not_after
FROM ct.domain_certs
WHERE reversed_domain = 'com.example' OR reversed_domain LIKE 'com.example.%'
ORDER BY seen DESC;
```

Compute the reversed key for a domain:

```sql
SELECT arrayStringConcat(arrayReverse(splitByChar('.', 'mail.example.com')), '.');
-- com.example.mail
```

## Configuration

| Setting | Where | Default |
|---|---|---|
| ClickHouse user/password/db | `.env` | `default` / `changeme` / `ct` |
| Batch size / flush interval | `ingester` env in `docker-compose.yml` | 5000 rows / 2s |
| CT logs followed | `certstream/config.yaml` | Google default log list |

ClickHouse HTTP (`8123`) and native (`9000`) ports are bound to `127.0.0.1` only.

## Notes & scope

- **Storage**: only `sha256` is kept (as the dedup key, raw `FixedString(32)` bytes —
  use `hex()`/`unhex()`); `sha1`, `fingerprint` and `serial_number` are dropped as unused.
  Text/array columns use `ZSTD(1)`, timestamps use `Delta, ZSTD(1)`.
- **Dedup**: a cert is logged to multiple CT logs. `ReplacingMergeTree` collapses
  duplicates by `sha256` (eventual) — use `FINAL` or `uniqExact(sha256)` for exact counts.
- **Recovery / gap-filling**: certstream checkpoints each log's index to a persisted
  volume (`certstream-state`) every 30s and on shutdown, and resumes from there after a
  restart — filling the downtime gap (duplicates dedup by `sha256`). The one-shot `seed`
  service writes the file at each log's current tip first, so a fresh deploy resumes from
  "now" rather than backfilling the entire history. The seeder is idempotent and
  self-healing: it only fetches tips for logs missing from the file. **Any watched log not
  in the seed backfills from index 0** — re-run `docker compose run --rm seed` if logs are
  added. To force a tip reset, wipe the file first:
  `docker compose run --rm --entrypoint sh seed -c 'rm -f /state/ct_index.json* && python /app/seed_ct_index.py'`.
- **Backfill** of full historical logs is out of scope; the stack ingests from the live tip.
- **Retention**: add `TTL seen + INTERVAL N MONTH` to the tables if storage is bounded.
