# cert-monitoring

Capture the live Certificate Transparency (CT) feed and store it in ClickHouse so
you can **query certificates by domain** — exact (`mail.example.com`) and
subdomain/suffix (everything under `example.com`).

```
ctmon seed (one-shot) ─▶ ct_index.json
                              │
certstream-server-go ──ws(/lite)──▶ ctmon (monitor) ──batch INSERT──▶ ClickHouse
                                     │  ingest          ├─ certs ──MV──▶ domain_certs
                                     │                  └─ cert_sightings (index ledger)
                                     └  detect gaps ──fetch missing entries (RFC6962 + tiled)──▶ certs + sightings
```

`ctmon` is a single Go binary (one shared `certRow` + insert path, so streamed and
backfilled rows can't drift):

- **`ctmon seed`** — one-shot job that writes each CT log's current tip to `ct_index.json` so certstream's recovery resumes from "now" instead of backfilling from 0. Idempotent + 429-aware; runs before certstream.
- **`ctmon` (monitor)** — runs two things concurrently: (a) **ingest** — consume the certstream lite WebSocket and batch into `ct.certs` + the `ct.cert_sightings` ledger; reads are decoupled from inserts so a slow/contended ClickHouse can't stall the socket and make certstream drop messages; (b) **backfill** — detect index-sequence gaps and refill them from the source log (RFC6962 `get-entries` + tiled tiles).
- **certstream-server-go** — streams parsed CT entries over WebSocket (lite stream, metadata only); `recovery` enabled so it resumes after a restart.
- **ClickHouse** — `ct.certs` (one row per cert) + `ct.domain_certs` (per domain, via materialized view) + `ct.cert_sightings` (raw per-log index ledger for gap detection).

## Quick start

```bash
cp .env.example .env          # set CLICKHOUSE_PASSWORD
docker compose up -d --build
docker compose ps             # clickhouse healthy, certstream + monitor up (seed exits 0)
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

# Monitor logs (ingest + backfill)
docker compose logs -f monitor
```

## Web UI

- **Grafana** — `http://localhost:3000`, bundled with the official ClickHouse datasource
  and a starter dashboard ("CT Monitoring — Overview": ingest rate, unique certs/domains,
  top root domains, top issuers, open-gap count), all auto-provisioned. Anonymous viewing
  is on; log in as `admin` / `CLICKHOUSE_PASSWORD` to edit. (Some all-time aggregation
  panels take ~10s on a large dataset; scope them to the time range to speed up.)
- **Built-in ClickHouse UIs** (no setup) — `http://localhost:8123/play` (SQL console +
  table results) and `http://localhost:8123/dashboard` (charts).

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
| Batch size / flush interval / retry buffer | `monitor` env in `docker-compose.yml` | 50000 rows / 5s / 500k rows |
| Backfill interval / max auto-repair gap | `monitor` env in `docker-compose.yml` | 2m / 100000 entries |
| Backfill concurrency / per-fetch retries | `monitor` env in `docker-compose.yml` | 6 logs / 6 attempts |
| CT logs followed | `certstream/config.yaml` | Google default log list |

ClickHouse HTTP (`8123`) and native (`9000`) ports are bound to `127.0.0.1` only.

## Notes & scope

- **Storage**: only `sha256` is kept (as the dedup key, raw `FixedString(32)` bytes —
  use `hex()`/`unhex()`); `sha1`, `fingerprint` and `serial_number` are dropped as unused.
  Text/array columns use `ZSTD(1)`, timestamps use `Delta, ZSTD(1)`.
- **Dedup**: a cert is logged to multiple CT logs. `ReplacingMergeTree` collapses
  duplicates by `sha256` (eventual) — use `FINAL` or `uniqExact(sha256)` for exact counts.
- **Ingest throughput**: per ClickHouse guidance, rows are batched client-side into
  10k–100k-row inserts (`BATCH_SIZE`/`BATCH_SECONDS`, ~1 insert/s) rather than many small
  ones. The WebSocket reader only appends to an in-memory buffer; a separate goroutine owns
  all inserts — so insert latency (or backfill contention) never stalls the socket and
  causes certstream to drop messages. Inserts are idempotent (retries are backstopped by
  the `ReplacingMergeTree` dedup).
- **Data integrity / gap repair**: the monitor writes a raw `cert_sightings` ledger
  (`source_url`, `cert_index`) that — unlike the deduped `certs` table — preserves each
  log's index continuity. Backfill detects holes (jumps in `cert_index` per log) and
  refetches the missing entries from the source log, inserting rows identical to the live
  stream (same `sha256` key). Logs are repaired in parallel (`BACKFILL_CONCURRENCY`);
  per-fetch errors retry with jittered backoff honoring `Retry-After` (`BACKFILL_RETRIES`),
  and hard statuses (e.g. 403) fail fast. Tiled logs are fetched as full tiles where
  complete and partial tiles (`.p/<width>`) at the tail. It runs on start + every
  `BACKFILL_INTERVAL`; gaps larger than `MAX_GAP` are logged for manual review. Inspect
  current gaps directly:
  ```sql
  SELECT source_url, toUInt64(prev_idx+1) AS gap_start, toUInt64(cert_index-1) AS gap_end,
         toUInt64(cert_index-prev_idx-1) AS missing
  FROM (SELECT source_url, cert_index, lagInFrame(cert_index) OVER w AS prev_idx
        FROM (SELECT source_url, cert_index FROM cert_sightings GROUP BY source_url, cert_index)
        WINDOW w AS (PARTITION BY source_url ORDER BY cert_index ROWS BETWEEN 1 PRECEDING AND CURRENT ROW))
  WHERE prev_idx != 0 AND cert_index - prev_idx > 1 ORDER BY missing DESC;
  ```
  `docker compose restart monitor` triggers an immediate detect+repair cycle.
- **Resilience**: every service is `restart: always`; ClickHouse data and certstream's
  recovery checkpoint are on durable volumes. A ClickHouse restart becomes a delay (the
  monitor buffers up to `MAX_BUFFER` rows and retries), not data loss. A monitor outage
  while certstream runs leaves a gap that backfill repairs on its next cycle.
- **Recovery / gap-filling**: certstream checkpoints each log's index to a persisted
  volume (`certstream-state`) every 30s and on shutdown, and resumes from there after a
  restart — filling the downtime gap (duplicates dedup by `sha256`). The one-shot `seed`
  service writes the file at each log's current tip first, so a fresh deploy resumes from
  "now" rather than backfilling the entire history. The seeder is idempotent and
  self-healing: it only fetches tips for logs missing from the file. **Any watched log not
  in the seed backfills from index 0** — re-run `docker compose run --rm seed` if logs are
  added. To force a tip reset, wipe the file first:
  `docker compose run --rm --entrypoint sh seed -c 'rm -f /state/ct_index.json* && /ctmon seed'`.
- **Backfill** is targeted gap-repair only (refilling holes in otherwise-streamed ranges).
  Bulk historical backfill from index 0 is still out of scope; the stack ingests from the
  live tip and repairs gaps within what it has seen.
- **Retention**: add `TTL seen + INTERVAL N MONTH` to the tables if storage is bounded.
