# CLAUDE.md

Agent guide for this repo. Human overview is in `README.md`; this file covers how to
work here and what's easy to get wrong.

## What this is

Captures the live Certificate Transparency feed (certstream-server-go) into ClickHouse,
queryable by domain, with gap detection + targeted backfill. Single Go service `ctmon`
(in `ctmon/`) + certstream + ClickHouse, wired by `docker-compose.yml`.

## Commands

No local Go/Python toolchain is assumed — everything runs in Docker.

```bash
# Run the stack (builds ctmon)
cp .env.example .env                      # set CLICKHOUSE_PASSWORD
docker compose up -d --build

# Build / vet / format ctmon WITHOUT a local Go install
docker run --rm -v "$PWD/ctmon":/src -w /src golang:1.25 \
  sh -c "gofmt -w . && go vet ./... && go build -o /dev/null ."

# Query ClickHouse (always source .env first for the password)
set -a; . ./.env; set +a
docker compose exec -T clickhouse clickhouse-client --password "$CLICKHOUSE_PASSWORD" --database ct -q "SELECT ..."

# Logs / trigger an immediate backfill cycle
docker compose logs -f monitor
docker compose restart monitor
```

`ctmon` deps (go.mod/go.sum) are committed; the Dockerfile does `go mod download` (no
`go mod tidy` at build). If you add an import, run the build container above to refresh
go.sum, then commit it.

## Architecture

`ctmon` is one binary, two modes (see `ctmon/main.go`):
- `ctmon seed` (one-shot, compose service `seed`) → writes each log's current tip to
  `ct_index.json` so certstream recovery resumes from "now". Code in `seed.go`.
- `ctmon` (compose service `monitor`) → runs concurrently: **ingest** (`ingest.go`,
  certstream WS → ClickHouse) and **backfill** (`backfill.go`, detect gaps → fetch).
- Shared: `clickhouse.go` (conn + the `certRow` struct + `insertRows`), `ctlog.go`
  (HTTP, tile fetch/parse, retry-error type).

Tables (`clickhouse/init/01-schema.sql`): `certs` (one row/cert, `ReplacingMergeTree` on
`sha256`) → MV explodes into `domain_certs` (sorted by reversed domain) ; `cert_sightings`
(raw non-deduped `(source_url, cert_index)` ledger — the gap-detection signal).

## Critical invariants — easy to break

- **Schema contract lives in THREE places that must stay in sync**: the column list/order in
  `clickhouse/init/01-schema.sql`, the `certRow` struct, and the `Append(...)`/column order
  in `insertRows` (`ctmon/clickhouse.go`). Change one → change all three.
- **`clickhouse/init/*.sql` runs ONLY on a fresh ClickHouse volume** (docker-entrypoint-initdb).
  Editing it does NOT alter an existing DB — apply `ALTER`/recreate manually, or
  `docker compose down -v` to start clean.
- **`sha256` is stored as `FixedString(32)` raw bytes**, not hex. Query with `hex(sha256)` /
  `sha256 = unhex('...')`. Backfill must compute the same hash the stream stores (SHA-256 of
  the cert DER for x509, of `Precert.Submitted.Data` for precerts) or dedup won't match.
- **Never do ClickHouse inserts on the WebSocket reader's code path.** The reader must only
  append to an in-memory buffer; a separate goroutine owns inserts. If the reader blocks on
  an insert, it stops draining the socket and certstream silently drops messages → gaps in
  every log at once. (This was the original "gap treadmill" bug.)
- **`cert_sightings` is load-bearing** — it's the only place per-log index continuity
  survives (the `certs` dedup destroys it). Don't "optimize" it away. It can be TTL'd
  shorter than the query tables (it only needs the recent gap-detection window).

## Gotchas

- **Tiled logs (static-ct-api)**: S3-backed logs (e.g. Let's Encrypt) return `403` (not
  `404`) for a not-yet-written full tile. Fetch the full tile only for COMPLETE tiles
  (`tileIndex < size/256`); fetch the partial tile `.p/<width>` (`width = size % 256`) for
  the tail, re-deriving width from a fresh checkpoint on retry (it grows). See `fetchTiled`.
- **Retries**: `withRetry` honors `Retry-After` and fails fast on non-retryable statuses
  (4xx except 408/429). RFC6962 fetches go through ctgo's `client` (its own 429 handling);
  tiled/seed go through our `httpGet`.
- **Restarting `monitor` creates real gaps** — each restart is a brief ingest outage while
  certstream keeps streaming, so every active log gets a hole that backfill then heals.
  Expect a burst of gap-repair after any `monitor` restart; it's not a bug.
- **certstream recovery without a seed = full history backfill from index 0.** The `seed`
  step must cover every watched log; a watched log missing from `ct_index.json` backfills
  from 0. Seeder is idempotent/merge (only fills missing logs) and 429-aware.
- **Counts**: `ReplacingMergeTree` dedup is eventual — use `uniqExact(sha256)` (or `FINAL`)
  for exact cert counts; raw `count()` includes not-yet-merged duplicates.

## Verifying gap repair end-to-end

Make a synthetic gap, then `docker compose restart monitor` (triggers an immediate cycle):
```sql
DELETE FROM ct.cert_sightings WHERE source_url='<url>' AND cert_index BETWEEN <a> AND <b>;
DELETE FROM ct.certs          WHERE source_url='<url>' AND cert_index BETWEEN <a> AND <b>;
```
Watch `docker compose logs monitor` for `backfilled <url> [a..b]` and `backfill complete`.
