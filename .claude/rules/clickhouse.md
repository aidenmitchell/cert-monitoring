# ClickHouse rules

Condensed ClickHouse best practices for this repo. **Read before editing
`clickhouse/init/*.sql` or any query in `ctmon`/`webui`.** Each rule links the
source doc and notes how this codebase already applies it.

## Data types — https://clickhouse.com/docs/best-practices/select-data-types
Pick the narrowest type that fits. `LowCardinality(String)` for columns with
**< ~10k distinct values**; plain `String` above that. Avoid `Nullable` (it adds
a separate null-tracking column) — use `''`/`0` defaults instead. `FixedString(N)`
only for strictly fixed-length values. Prefer `DateTime` over `DateTime64` unless
sub-second precision is essential. Smallest integer width for the range.
- **Here:** `sha256 FixedString(32)`; `source_url`/`source_name`/`source_type`/
  `update_type`/`signature_algorithm`/`issuer_o`/`issuer_cn`/`subject_o` are
  `LowCardinality`; high-cardinality `subject_cn`/`domain` stay `String`; no
  `Nullable` (ingester coalesces to `''`); `cert_index UInt64` (CT indices exceed
  UInt32's 4.29B).

## Primary key / ORDER BY — https://clickhouse.com/docs/best-practices/choosing-a-primary-key
`ORDER BY` builds the sparse primary index. Lead with the column(s) you filter on
most; order roughly low→high cardinality for compression; keep the key short.
Design it around the dominant query, not an "id".
- **Here:** `domain_certs ORDER BY (reversed_domain, seen, sha256)` makes
  domain/subdomain lookups a PK range scan (the core query); `certs ORDER BY
  (sha256)` is the dedup identity; `cert_sightings ORDER BY (source_url,
  cert_index)` serves per-log gap scans.

## Materialized views — https://clickhouse.com/docs/best-practices/use-materialized-views
Incremental MVs transform/aggregate at INSERT time into a target table — great for
a fixed, frequent query shape. They only see each insert block (not history), so
backfill the target separately; insert cost scales with MV count.
- **Here:** `mv_domain_certs` `arrayJoin`s `certs.all_domains` into `domain_certs`
  with the reversed-domain key. Ingester writes only `certs`; the MV fans out.
  Backfill also inserts into `certs`, so the MV repopulates `domain_certs`.

## Joins — https://clickhouse.com/docs/best-practices/minimize-optimize-joins
Joins are comparatively expensive — prefer denormalization or dictionaries. If you
must join, the right-hand table is the build side, so put the smaller one there.
- **Here:** no query-time joins. `domain_certs` is denormalized (carries `domain`,
  `seen`, `not_*`, `issuer_o`, `source_name`) so domain queries never join back to
  `certs`.

## Partitioning — https://clickhouse.com/docs/best-practices/choosing-a-partitioning-key
Partition for **data management** (TTL, drops, backups), not query speed. Keep the
partition count low — a high-cardinality partition key explodes parts and wrecks
performance. Monthly (`toYYYYMM`) is the usual choice.
- **Here:** all three tables `PARTITION BY toYYYYMM(seen)` — coarse, enables
  month-granular TTL/drops without part explosion. Don't partition finer (day,
  `source_url`, …).

## Insert strategy — https://clickhouse.com/docs/best-practices/selecting-an-insert-strategy
Batch client-side: **10k–100k rows/insert, ~1 insert/sec/table**. Inserts are
idempotent (retry the same block; `ReplacingMergeTree` also dedups). Use
`async_insert` only when client-side batching isn't feasible (many small clients).
- **Here:** `ctmon` batches 50k rows / 5s and the WS reader is decoupled from
  inserts (reads never block). Retries keep the buffer; `ReplacingMergeTree`
  backstops dedup.

## Data-skipping indices — https://clickhouse.com/docs/best-practices/use-data-skipping-indices-where-appropriate
Add a skip index only for a **selective** filter on a **non-primary-key** column;
it lets ClickHouse skip granules. `bloom_filter` for equality/`has()`, `minmax`
for loosely-sorted ranges, `tokenbf`/`text` for substrings. Don't over-add (insert
+ storage cost); verify with `EXPLAIN indexes = 1`.
- **Here:** `INDEX idx_domains all_domains TYPE bloom_filter GRANULARITY 3` on
  `certs` for fast `has(all_domains, 'x')`.

## Avoid mutations — https://clickhouse.com/docs/best-practices/avoid-mutations
`ALTER TABLE … UPDATE/DELETE` rewrite whole parts — never use them for routine or
per-row changes. Model updates as inserts (`ReplacingMergeTree`/versioning) and
deletes as TTL or `DROP PARTITION`.
- **Here:** dedup is `ReplacingMergeTree`, not `UPDATE`; the pipeline runs no
  mutations. The one-off cleanup `DELETE` and the `LowCardinality ALTER MODIFY`
  were deliberate one-time ops, not part of steady state.

## Avoid OPTIMIZE FINAL — https://clickhouse.com/docs/best-practices/avoid-optimize-final
Don't run `OPTIMIZE TABLE … FINAL` routinely — it rewrites every part and is very
expensive. Let background merges collapse `ReplacingMergeTree` duplicates; for
exact reads use the `FINAL` modifier or `GROUP BY`/`uniqExact` at query time.
- **Here:** counts use `uniqExact(sha256)`; we never schedule `OPTIMIZE FINAL`.

## JSON type — https://clickhouse.com/docs/best-practices/use-json-where-appropriate
Use the `JSON` type for genuinely semi-structured/variable data — not for known
fields, where explicit columns are faster and smaller.
- **Here:** all stored cert fields are explicit columns (no JSON). If we ever keep
  raw cert extensions / variable metadata, reach for `JSON` rather than a `String`
  blob.
