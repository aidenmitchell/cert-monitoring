package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	ctx509 "github.com/google/certificate-transparency-go/x509"
)

// Gap is a contiguous run of missing indices [Start, End] within one log.
type Gap struct {
	SourceURL  string
	SourceType string
	Start, End uint64
	Missing    uint64
}

// A gap is a jump in cert_index within a source_url in the (non-deduped) ledger.
const detectSQL = `
SELECT source_url, source_type,
       toUInt64(prev_idx + 1)              AS gap_start,
       toUInt64(cert_index - 1)            AS gap_end,
       toUInt64(cert_index - prev_idx - 1) AS missing
FROM (
    SELECT source_url, source_type, cert_index,
           lagInFrame(cert_index) OVER w AS prev_idx
    FROM (SELECT source_url, any(source_type) AS source_type, cert_index
          FROM cert_sightings GROUP BY source_url, cert_index)
    WINDOW w AS (PARTITION BY source_url ORDER BY cert_index ASC ROWS BETWEEN 1 PRECEDING AND CURRENT ROW)
)
WHERE prev_idx != 0 AND (cert_index - prev_idx) > 1
ORDER BY missing DESC`

func runBackfillLoop(ctx context.Context, cfg config, conn driver.Conn) {
	runBackfillCycle(ctx, cfg, conn) // on start
	t := time.NewTicker(cfg.backfillInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			runBackfillCycle(ctx, cfg, conn)
		}
	}
}

func runBackfillCycle(ctx context.Context, cfg config, conn driver.Conn) {
	started := time.Now()
	gaps, err := detectGaps(ctx, conn)
	if err != nil {
		log.Printf("gap detection failed: %v", err)
		return
	}
	if len(gaps) == 0 {
		log.Println("no gaps detected")
		return
	}

	// Group gaps by log, then repair logs in parallel (bounded) while keeping a
	// single log's gaps sequential — so we hit many providers at once without
	// hammering any one of them.
	byLog := map[string][]Gap{}
	var order []string
	for _, g := range gaps {
		if _, ok := byLog[g.SourceURL]; !ok {
			order = append(order, g.SourceURL)
		}
		byLog[g.SourceURL] = append(byLog[g.SourceURL], g)
	}
	log.Printf("detected %d gap(s) across %d log(s); repairing (concurrency=%d)",
		len(gaps), len(order), cfg.backfillConcurrency)

	var (
		mu                                 sync.Mutex
		entries, repaired, skipped, failed int
		wg                                 sync.WaitGroup
		sem                                = make(chan struct{}, cfg.backfillConcurrency)
	)
	for _, url := range order {
		wg.Add(1)
		sem <- struct{}{}
		go func(grp []Gap) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, g := range grp {
				if ctx.Err() != nil {
					return
				}
				if g.Missing > cfg.maxGap {
					log.Printf("SKIP gap %s [%d..%d] missing=%d exceeds MAX_GAP=%d (manual review)",
						g.SourceURL, g.Start, g.End, g.Missing, cfg.maxGap)
					mu.Lock()
					skipped++
					mu.Unlock()
					continue
				}
				n, err := backfill(ctx, cfg, conn, g)
				mu.Lock()
				switch {
				case err != nil:
					failed++
					log.Printf("backfill %s [%d..%d] failed after %d rows: %v", g.SourceURL, g.Start, g.End, n, err)
				case n > 0:
					repaired++
					entries += n
					log.Printf("backfilled %s [%d..%d]: %d entries", g.SourceURL, g.Start, g.End, n)
				}
				mu.Unlock()
			}
		}(byLog[url])
	}
	wg.Wait()

	log.Printf("backfill complete in %s: %d/%d gaps repaired (%d entries), %d skipped (>MAX_GAP), %d failed",
		time.Since(started).Round(time.Second), repaired, len(gaps), entries, skipped, failed)
}

// withRetry runs fn, retrying transient CT-log errors (e.g. 429) with capped
// exponential backoff. If the log sends a Retry-After header we honor it; if it
// returns a hard status (e.g. 403), we fail fast instead of hammering it.
func withRetry(ctx context.Context, attempts int, what string, fn func() error) error {
	var err error
	for a := 0; a < attempts; a++ {
		if err = fn(); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var fe *fetchErr
		if errors.As(err, &fe) && !retryableStatus(fe.status) {
			return err // hard error (4xx) — retrying won't help
		}
		wait := backoffDur(a)
		if errors.As(err, &fe) && fe.retryAfter > 0 {
			wait = fe.retryAfter // honor the log's Retry-After
		}
		log.Printf("  retry %s in %s (attempt %d/%d): %v", what, wait, a+1, attempts, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return err
}

func detectGaps(ctx context.Context, conn driver.Conn) ([]Gap, error) {
	rows, err := conn.Query(ctx, detectSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var gaps []Gap
	for rows.Next() {
		var g Gap
		if err := rows.Scan(&g.SourceURL, &g.SourceType, &g.Start, &g.End, &g.Missing); err != nil {
			return nil, err
		}
		gaps = append(gaps, g)
	}
	return gaps, rows.Err()
}

func lookupSourceName(ctx context.Context, conn driver.Conn, sourceURL string) string {
	var name string
	_ = conn.QueryRow(ctx, "SELECT any(source_name) FROM certs WHERE source_url = ?", sourceURL).Scan(&name)
	return name
}

func backfill(ctx context.Context, cfg config, conn driver.Conn, g Gap) (int, error) {
	sourceName := lookupSourceName(ctx, conn, g.SourceURL)
	var (
		rows []certRow
		err  error
	)
	switch g.SourceType {
	case "rfc6962":
		rows, err = fetchRFC6962(ctx, cfg, g, sourceName)
	case "tiled":
		rows, err = fetchTiled(ctx, cfg, g, sourceName)
	default:
		return 0, fmt.Errorf("unknown source_type %q", g.SourceType)
	}
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	if err := insertRows(ctx, conn, rows); err != nil {
		return 0, fmt.Errorf("insert: %w", err)
	}
	return len(rows), nil
}

func fetchRFC6962(ctx context.Context, cfg config, g Gap, sourceName string) ([]certRow, error) {
	lc, err := client.New(g.SourceURL, httpClient, jsonclient.Options{UserAgent: userAgent})
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}
	var rows []certRow
	for start := g.Start; start <= g.End; {
		end := start + uint64(cfg.rfcChunk) - 1
		if end > g.End {
			end = g.End
		}
		var resp *ct.GetEntriesResponse
		err := withRetry(ctx, cfg.backfillRetries,
			fmt.Sprintf("get-entries %s [%d..%d]", g.SourceURL, start, end), func() error {
				r, e := lc.GetRawEntries(ctx, int64(start), int64(end))
				if e != nil {
					return e
				}
				if len(r.Entries) == 0 {
					return fmt.Errorf("returned 0 entries")
				}
				resp = r
				return nil
			})
		if err != nil {
			return rows, fmt.Errorf("get-entries [%d..%d]: %w", start, end, err)
		}
		for i := range resp.Entries {
			idx := start + uint64(i)
			rle, err := ct.RawLogEntryFromLeaf(int64(idx), &resp.Entries[i])
			if err != nil {
				log.Printf("  skip entry %d (%s): %v", idx, g.SourceURL, err)
				continue
			}
			if row, err := buildRow(rle, idx, g, sourceName); err == nil {
				rows = append(rows, row)
			} else {
				log.Printf("  skip entry %d (%s): %v", idx, g.SourceURL, err)
			}
		}
		start += uint64(len(resp.Entries)) // logs may return fewer than requested
	}
	return rows, nil
}

func fetchTiled(ctx context.Context, cfg config, g Gap, sourceName string) ([]certRow, error) {
	base := strings.TrimRight(g.SourceURL, "/")
	var size uint64
	if err := withRetry(ctx, cfg.backfillRetries, "checkpoint "+g.SourceURL, func() error {
		s, e := fetchCheckpointSize(ctx, base)
		if e != nil {
			return e
		}
		size = s
		return nil
	}); err != nil {
		return nil, fmt.Errorf("checkpoint: %w", err)
	}
	// Tiles below size/tileSize are complete and immutable; the one at
	// size/tileSize is the still-growing tail (fetched as a partial tile). All
	// gap indices are < size, so every one lives in a fetchable tile.
	completeTiles := size / tileSize
	var rows []certRow
	for tileIndex := g.Start / tileSize; tileIndex <= g.End/tileSize; tileIndex++ {
		var leaves []tileLeaf
		isFull := tileIndex < completeTiles
		err := withRetry(ctx, cfg.backfillRetries,
			fmt.Sprintf("tile %d %s", tileIndex, g.SourceURL), func() error {
				width := uint64(0) // 0 = full tile
				if !isFull {
					// Tail tile: re-derive the current width each attempt — it
					// grows, and may complete into a full tile, as the log advances.
					s, e := fetchCheckpointSize(ctx, base)
					if e != nil {
						return e
					}
					switch {
					case s/tileSize > tileIndex:
						width = 0 // completed since; fetch the full tile
					case s/tileSize == tileIndex && s%tileSize > 0:
						width = s % tileSize
					default:
						return fmt.Errorf("tile %d not yet available (size=%d)", tileIndex, s)
					}
				}
				l, e := fetchTile(ctx, base, tileIndex, width)
				if e != nil {
					return e
				}
				leaves = l
				return nil
			})
		if err != nil {
			return rows, fmt.Errorf("tile %d: %w", tileIndex, err)
		}
		baseIdx := tileIndex * tileSize
		for i := range leaves {
			idx := baseIdx + uint64(i)
			if idx < g.Start || idx > g.End {
				continue
			}
			rle := convertTileLeaf(leaves[i], idx)
			if row, err := buildRow(rle, idx, g, sourceName); err == nil {
				rows = append(rows, row)
			} else {
				log.Printf("  skip entry %d (%s): %v", idx, g.SourceURL, err)
			}
		}
	}
	return rows, nil
}

// buildRow mirrors certstream's parseData/leafCertFromX509cert for the fields we
// store, so backfilled rows match the live stream — notably the sha256 key
// (SHA-256 of the cert DER for x509, of the submitted precert otherwise).
func buildRow(rle *ct.RawLogEntry, idx uint64, g Gap, sourceName string) (certRow, error) {
	le, err := rle.ToLogEntry()
	if err != nil {
		return certRow{}, fmt.Errorf("to-log-entry: %w", err)
	}
	var cert *ctx509.Certificate
	var rawForHash []byte
	switch {
	case le.X509Cert != nil:
		cert = le.X509Cert
		rawForHash = le.X509Cert.Raw
	case le.Precert != nil:
		cert = le.Precert.TBSCertificate
		if len(le.Precert.Submitted.Data) > 0 {
			rawForHash = le.Precert.Submitted.Data
		} else {
			rawForHash = cert.Raw // tiled precerts carry no submitted cert
		}
	default:
		return certRow{}, fmt.Errorf("no cert in entry")
	}
	sum := sha256.Sum256(rawForHash)

	domains := append([]string{}, cert.DNSNames...)
	if cn := cert.Subject.CommonName; cn != "" && !cert.IsCA && !slices.Contains(domains, cn) {
		domains = append(domains, cn)
	}
	var isCA uint8
	if cert.IsCA {
		isCA = 1
	}
	return certRow{
		sha256:             sum[:],
		seen:               time.Now().UTC(),
		notBefore:          cert.NotBefore,
		notAfter:           cert.NotAfter,
		allDomains:         domains,
		subjectCN:          cert.Subject.CommonName,
		subjectO:           strings.Join(cert.Subject.Organization, ","),
		issuerCN:           cert.Issuer.CommonName,
		issuerO:            strings.Join(cert.Issuer.Organization, ","),
		signatureAlgorithm: sigAlg(cert.SignatureAlgorithm),
		isCA:               isCA,
		updateType:         "X509LogEntry",
		sourceName:         sourceName,
		sourceURL:          g.SourceURL,
		sourceType:         g.SourceType,
		certIndex:          idx,
	}, nil
}

func sigAlg(s ctx509.SignatureAlgorithm) string {
	switch s {
	case ctx509.MD2WithRSA:
		return "md2, rsa"
	case ctx509.MD5WithRSA:
		return "md5, rsa"
	case ctx509.SHA1WithRSA:
		return "sha1, rsa"
	case ctx509.SHA256WithRSA:
		return "sha256, rsa"
	case ctx509.SHA384WithRSA:
		return "sha384, rsa"
	case ctx509.SHA512WithRSA:
		return "sha512, rsa"
	case ctx509.SHA256WithRSAPSS:
		return "sha256, rsa-pss"
	case ctx509.SHA384WithRSAPSS:
		return "sha384, rsa-pss"
	case ctx509.SHA512WithRSAPSS:
		return "sha512, rsa-pss"
	case ctx509.DSAWithSHA1:
		return "dsa, sha1"
	case ctx509.DSAWithSHA256:
		return "dsa, sha256"
	case ctx509.ECDSAWithSHA1:
		return "ecdsa, sha1"
	case ctx509.ECDSAWithSHA256:
		return "ecdsa, sha256"
	case ctx509.ECDSAWithSHA384:
		return "ecdsa, sha384"
	case ctx509.ECDSAWithSHA512:
		return "ecdsa, sha512"
	case ctx509.PureEd25519:
		return "ed25519"
	default:
		return "unknown"
	}
}
