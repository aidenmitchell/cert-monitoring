-- CT log storage schema. Auto-run on first ClickHouse start via
-- /docker-entrypoint-initdb.d. Idempotent so re-runs are safe.
--
-- Compression: ZSTD(1) on text/array columns, Delta+ZSTD on timestamps
-- (near-sorted values -> tiny deltas). LowCardinality columns are already
-- dictionary-encoded. ClickHouse defaults to LZ4 if no CODEC is given.
--
-- sha256 is kept as the per-cert identity / dedup key, stored as raw bytes
-- FixedString(32) (~3x smaller than the colon-hex string, and it's the sort
-- key so the primary index shrinks too). Read/write with hex()/unhex().
-- sha1, fingerprint and serial_number are intentionally NOT stored — unused.

CREATE DATABASE IF NOT EXISTS ct;

-- ---------------------------------------------------------------------------
-- Table 1: one row per certificate (full metadata).
-- ReplacingMergeTree keyed on sha256 collapses the same cert seen across
-- multiple CT logs. Dedup is eventual — use FINAL or GROUP BY sha256 when
-- exact counts matter at query time.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ct.certs
(
    sha256              FixedString(32),
    seen                DateTime64(3)        CODEC(Delta, ZSTD(1)),
    not_before          DateTime             CODEC(Delta, ZSTD(1)),
    not_after           DateTime             CODEC(Delta, ZSTD(1)),
    all_domains         Array(String)        CODEC(ZSTD(1)),
    subject_cn          String               CODEC(ZSTD(1)),
    subject_o           LowCardinality(String),
    issuer_cn           String               CODEC(ZSTD(1)),
    issuer_o            LowCardinality(String),
    signature_algorithm LowCardinality(String),
    is_ca               UInt8,
    update_type         LowCardinality(String),   -- X509LogEntry | PrecertLogEntry
    source_name         LowCardinality(String),
    source_url          String               CODEC(ZSTD(1)),
    source_type         LowCardinality(String),   -- rfc6962 | tiled
    cert_index          UInt64               CODEC(ZSTD(1)),
    -- ~10x speedup for has(all_domains, 'x') exact lookups (Altinity-tested
    -- sweet spot: default FPR, GRANULARITY 3 for array columns).
    INDEX idx_domains all_domains TYPE bloom_filter GRANULARITY 3
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(seen)
ORDER BY (sha256)
SETTINGS index_granularity = 8192;

-- ---------------------------------------------------------------------------
-- Table 2: one row per (domain, cert sighting), sorted by reversed domain.
-- reversed_domain ('www.example.com' -> 'com.example.www') as the leftmost
-- ORDER BY column turns "all subdomains of example.com" into a primary-key
-- RANGE SCAN (LIKE 'com.example.%') instead of a full scan.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ct.domain_certs
(
    reversed_domain String          CODEC(ZSTD(1)),
    domain          String          CODEC(ZSTD(1)),
    sha256          FixedString(32),
    seen            DateTime64(3)    CODEC(Delta, ZSTD(1)),
    not_before      DateTime         CODEC(Delta, ZSTD(1)),
    not_after       DateTime         CODEC(Delta, ZSTD(1)),
    issuer_o        LowCardinality(String),
    source_name     LowCardinality(String)
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(seen)
ORDER BY (reversed_domain, seen, sha256);

-- ---------------------------------------------------------------------------
-- Table 3: raw per-(log, index) ledger for gap detection. NOT deduped across
-- logs (each log has its own index sequence), so unlike ct.certs it preserves
-- per-log index continuity. The ingester writes here directly. A gap = a jump
-- in cert_index within a source_url. source_type/source_url let the backfiller
-- pick the fetch protocol + endpoint.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ct.cert_sightings
(
    source_url   LowCardinality(String),
    source_type  LowCardinality(String),   -- rfc6962 | tiled
    cert_index   UInt64,
    seen         DateTime64(3)             CODEC(Delta, ZSTD(1))
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(seen)
ORDER BY (source_url, cert_index);

-- ---------------------------------------------------------------------------
-- Materialized View: explode all_domains into domain_certs on insert.
-- The ingester writes ONLY to ct.certs; this fans out automatically.
-- ---------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS ct.mv_domain_certs TO ct.domain_certs AS
SELECT
    arrayStringConcat(arrayReverse(splitByChar('.', d)), '.') AS reversed_domain,
    d                                                          AS domain,
    sha256,
    seen,
    not_before,
    not_after,
    issuer_o,
    source_name
FROM ct.certs
ARRAY JOIN all_domains AS d;
