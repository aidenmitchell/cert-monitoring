-- Example queries for the CT log store. Run with:
--   docker compose exec clickhouse clickhouse-client --database ct --password "$CLICKHOUSE_PASSWORD"
--
-- Note: the same cert is logged to multiple CT logs. ReplacingMergeTree
-- collapses duplicates by sha256 eventually; for exact counts use FINAL or
-- uniqExact(sha256). sha256 is stored as raw bytes — display with hex(sha256),
-- filter with sha256 = unhex('ABCD..').

-- Reversed-domain helper (compute the key for an exact lookup):
--   SELECT arrayStringConcat(arrayReverse(splitByChar('.', 'mail.example.com')), '.');
--   -> 'com.example.mail'

-- 1) Exact domain — primary-key point lookup on domain_certs.
SELECT domain, seen, not_after, issuer_o
FROM ct.domain_certs
WHERE reversed_domain = 'com.example.mail'
ORDER BY seen DESC
LIMIT 100;

-- 2) Domain + all subdomains (the main use case) — primary-key RANGE SCAN.
SELECT domain, seen, not_after, issuer_o
FROM ct.domain_certs
WHERE reversed_domain = 'com.example'
   OR reversed_domain LIKE 'com.example.%'
ORDER BY seen DESC
LIMIT 100;

-- 3) Full metadata for a single exact name — uses the bloom filter on certs.
SELECT seen, not_before, not_after, subject_cn, issuer_o, source_name
FROM ct.certs
WHERE has(all_domains, 'mail.example.com')
ORDER BY seen DESC
LIMIT 100;

-- 4) Top root (registrable) domains by distinct certs and names.
SELECT
    cutToFirstSignificantSubdomain(domain) AS root_domain,
    uniqExact(sha256)                      AS distinct_certs,
    uniqExact(domain)                      AS distinct_names
FROM ct.domain_certs
GROUP BY root_domain
ORDER BY distinct_certs DESC
LIMIT 20;

-- 5) New distinct subdomains under a parent in the last hour (monitoring).
SELECT DISTINCT domain
FROM ct.domain_certs
WHERE reversed_domain LIKE 'com.example.%'
  AND seen > now() - INTERVAL 1 HOUR
ORDER BY domain;

-- 6) Top issuers by volume.
SELECT issuer_o, count() AS certs
FROM ct.certs
WHERE issuer_o != ''
GROUP BY issuer_o
ORDER BY certs DESC
LIMIT 20;

-- Confirm the index/PK is actually used:
--   EXPLAIN indexes = 1
--   SELECT count() FROM ct.domain_certs WHERE reversed_domain LIKE 'com.example.%';
--   EXPLAIN indexes = 1
--   SELECT count() FROM ct.certs WHERE has(all_domains, 'mail.example.com');
