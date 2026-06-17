// backfiller detects gaps in our stored CT data (holes in each log's
// cert_index sequence) and repairs them by fetching the missing entries
// directly from the source log — RFC6962 via get-entries, tiled via tile
// fetches — then inserting rows identical to what the live ingester writes.
//
// It runs once on start and then on an interval. Gaps larger than MAX_GAP are
// logged and skipped so a huge hole can't trigger a surprise multi-million
// entry fetch.
package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"golang.org/x/crypto/cryptobyte"
)

const (
	userAgent = "cert-monitoring-backfiller/1.0"
	tileSize  = 256
)

type config struct {
	chAddr, chUser, chPass, chDB string
	interval                     time.Duration
	maxGap                       uint64
	rfcChunk                     int
}

func loadConfig() config {
	return config{
		chAddr:   env("CLICKHOUSE_HOST", "clickhouse") + ":" + env("CLICKHOUSE_PORT", "9000"),
		chUser:   env("CLICKHOUSE_USER", "default"),
		chPass:   env("CLICKHOUSE_PASSWORD", ""),
		chDB:     env("CLICKHOUSE_DB", "ct"),
		interval: envDuration("BACKFILL_INTERVAL", time.Hour),
		maxGap:   uint64(envInt("MAX_GAP", 100000)),
		rfcChunk: envInt("RFC_CHUNK", 256),
	}
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envInt(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

func envDuration(k string, d time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if t, err := time.ParseDuration(v); err == nil {
			return t
		}
	}
	return d
}

// Gap is a contiguous run of missing indices [Start, End] in one log.
type Gap struct {
	SourceURL  string
	SourceType string
	Start, End uint64
	Missing    uint64
}

// certRow mirrors the columns/order of ct.certs (see ingester CERT_COLUMNS).
type certRow struct {
	sha256                            []byte
	seen, notBefore, notAfter         time.Time
	allDomains                        []string
	subjectCN, subjectO               string
	issuerCN, issuerO                 string
	signatureAlgorithm                string
	isCA                              uint8
	updateType                        string
	sourceName, sourceURL, sourceType string
	certIndex                         uint64
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

func main() {
	cfg := loadConfig()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{cfg.chAddr},
		Auth: clickhouse.Auth{Database: cfg.chDB, Username: cfg.chUser, Password: cfg.chPass},
	})
	if err != nil {
		log.Fatalf("clickhouse open: %v", err)
	}
	defer conn.Close()
	log.Printf("backfiller up; clickhouse=%s db=%s interval=%s max_gap=%d",
		cfg.chAddr, cfg.chDB, cfg.interval, cfg.maxGap)

	runCycle(ctx, cfg, conn) // on start
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down")
			return
		case <-ticker.C:
			runCycle(ctx, cfg, conn)
		}
	}
}

func runCycle(ctx context.Context, cfg config, conn driver.Conn) {
	gaps, err := detectGaps(ctx, conn)
	if err != nil {
		log.Printf("gap detection failed: %v", err)
		return
	}
	if len(gaps) == 0 {
		log.Println("no gaps detected")
		return
	}
	log.Printf("detected %d gap(s)", len(gaps))
	for _, g := range gaps {
		if g.Missing > cfg.maxGap {
			log.Printf("SKIP gap %s [%d..%d] missing=%d exceeds MAX_GAP=%d (manual review)",
				g.SourceURL, g.Start, g.End, g.Missing, cfg.maxGap)
			continue
		}
		n, err := backfill(ctx, cfg, conn, g)
		if err != nil {
			log.Printf("backfill %s [%d..%d] failed after %d rows: %v", g.SourceURL, g.Start, g.End, n, err)
			continue
		}
		log.Printf("backfilled %s [%d..%d]: %d entries", g.SourceURL, g.Start, g.End, n)
	}
}

const detectSQL = `
SELECT source_url, source_type,
       toUInt64(prev_idx + 1)            AS gap_start,
       toUInt64(cert_index - 1)          AS gap_end,
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
	row := conn.QueryRow(ctx,
		"SELECT any(source_name) FROM certs WHERE source_url = ?", sourceURL)
	_ = row.Scan(&name)
	return name
}

// backfill fetches [g.Start, g.End] from the log, builds rows, and inserts them.
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
		rows, err = fetchTiled(ctx, g, sourceName)
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
		resp, err := lc.GetRawEntries(ctx, int64(start), int64(end))
		if err != nil {
			return rows, fmt.Errorf("get-entries [%d..%d]: %w", start, end, err)
		}
		if len(resp.Entries) == 0 {
			return rows, fmt.Errorf("get-entries [%d..%d] returned 0 entries", start, end)
		}
		for i := range resp.Entries {
			idx := start + uint64(i)
			rle, err := ct.RawLogEntryFromLeaf(int64(idx), &resp.Entries[i])
			if err != nil {
				log.Printf("  skip entry %d (%s): %v", idx, g.SourceURL, err)
				continue
			}
			row, err := buildRow(rle, idx, g, sourceName)
			if err != nil {
				log.Printf("  skip entry %d (%s): %v", idx, g.SourceURL, err)
				continue
			}
			rows = append(rows, row)
		}
		start += uint64(len(resp.Entries)) // logs may return fewer than requested
	}
	return rows, nil
}

func fetchTiled(ctx context.Context, g Gap, sourceName string) ([]certRow, error) {
	base := strings.TrimRight(g.SourceURL, "/")
	var rows []certRow
	for tileIndex := g.Start / tileSize; tileIndex <= g.End/tileSize; tileIndex++ {
		leaves, err := fetchTile(ctx, base, tileIndex)
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
			row, err := buildRow(rle, idx, g, sourceName)
			if err != nil {
				log.Printf("  skip entry %d (%s): %v", idx, g.SourceURL, err)
				continue
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

// fetchTile fetches a full data tile; if that 404s (the tile is still partial
// at the log head), it retries the partial tile sized from the checkpoint.
func fetchTile(ctx context.Context, base string, tileIndex uint64) ([]tileLeaf, error) {
	data, status, err := httpGet(ctx, fmt.Sprintf("%s/tile/data/%s", base, encodeTilePath(tileIndex)))
	if err == nil && status == http.StatusOK {
		return parseTileData(data)
	}
	if status != http.StatusNotFound {
		return nil, fmt.Errorf("fetch tile: status %d", status)
	}
	size, cpErr := fetchCheckpointSize(ctx, base)
	if cpErr != nil {
		return nil, fmt.Errorf("partial tile: %w", cpErr)
	}
	width := size % tileSize
	if size/tileSize != tileIndex || width == 0 {
		return nil, fmt.Errorf("tile %d not available", tileIndex)
	}
	data, status, err = httpGet(ctx, fmt.Sprintf("%s/tile/data/%s.p/%d", base, encodeTilePath(tileIndex), width))
	if err != nil || status != http.StatusOK {
		return nil, fmt.Errorf("fetch partial tile: status %d err %v", status, err)
	}
	return parseTileData(data)
}

func fetchCheckpointSize(ctx context.Context, base string) (uint64, error) {
	data, status, err := httpGet(ctx, base+"/checkpoint")
	if err != nil || status != http.StatusOK {
		return 0, fmt.Errorf("checkpoint status %d err %v", status, err)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("bad checkpoint")
	}
	return strconv.ParseUint(strings.TrimSpace(lines[1]), 10, 64)
}

func httpGet(ctx context.Context, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

// buildRow mirrors certstream's parseData/leafCertFromX509cert for the fields
// we store, so backfilled rows match the live stream (notably the sha256 key).
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
			rawForHash = le.Precert.Submitted.Data // matches the live stream
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

func insertRows(ctx context.Context, conn driver.Conn, rows []certRow) error {
	cb, err := conn.PrepareBatch(ctx, "INSERT INTO certs")
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := cb.Append(r.sha256, r.seen, r.notBefore, r.notAfter, r.allDomains,
			r.subjectCN, r.subjectO, r.issuerCN, r.issuerO, r.signatureAlgorithm,
			r.isCA, r.updateType, r.sourceName, r.sourceURL, r.sourceType, r.certIndex); err != nil {
			return err
		}
	}
	if err := cb.Send(); err != nil {
		return err
	}
	// Ledger: closes the gap so it isn't re-detected next cycle.
	sb, err := conn.PrepareBatch(ctx, "INSERT INTO cert_sightings")
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := sb.Append(r.sourceURL, r.sourceType, r.certIndex, r.seen); err != nil {
			return err
		}
	}
	return sb.Send()
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

// --- tiled tile parsing (ported from certstream-server-go ct-tiled.go) -------

type tileLeaf struct {
	timestamp     uint64
	entryType     uint16
	x509Entry     []byte
	precertEntry  []byte
	issuerKeyHash [32]byte
}

func encodeTilePath(index uint64) string {
	if index == 0 {
		return "000"
	}
	var groups []uint64
	for n := index; n > 0; n /= 1000 {
		groups = append(groups, n%1000)
	}
	var b strings.Builder
	for i := len(groups) - 1; i >= 0; i-- {
		if i < len(groups)-1 {
			b.WriteByte('/')
		}
		if i > 0 {
			b.WriteByte('x')
		}
		fmt.Fprintf(&b, "%03d", groups[i])
	}
	return b.String()
}

func parseTileData(data []byte) ([]tileLeaf, error) {
	var leaves []tileLeaf
	p := cryptobyte.String(data)
	for !p.Empty() {
		var leaf tileLeaf
		if !p.ReadUint64(&leaf.timestamp) || !p.ReadUint16(&leaf.entryType) {
			return nil, fmt.Errorf("tile header parse error")
		}
		switch leaf.entryType {
		case 0: // x509_entry
			var cert, extensions, fingerprints cryptobyte.String
			if !p.ReadUint24LengthPrefixed(&cert) ||
				!p.ReadUint16LengthPrefixed(&extensions) ||
				!p.ReadUint16LengthPrefixed(&fingerprints) {
				return nil, fmt.Errorf("x509_entry parse error")
			}
			leaf.x509Entry = append([]byte(nil), cert...)
		case 1: // precert_entry
			var defangedCrt, extensions, entry, fingerprints cryptobyte.String
			if !p.CopyBytes(leaf.issuerKeyHash[:]) ||
				!p.ReadUint24LengthPrefixed(&defangedCrt) ||
				!p.ReadUint16LengthPrefixed(&extensions) ||
				!p.ReadUint24LengthPrefixed(&entry) ||
				!p.ReadUint16LengthPrefixed(&fingerprints) {
				return nil, fmt.Errorf("precert_entry parse error")
			}
			leaf.precertEntry = append([]byte(nil), defangedCrt...)
		default:
			return nil, fmt.Errorf("unknown entry type %d", leaf.entryType)
		}
		leaves = append(leaves, leaf)
	}
	return leaves, nil
}

func convertTileLeaf(leaf tileLeaf, index uint64) *ct.RawLogEntry {
	rle := &ct.RawLogEntry{
		Index: int64(index),
		Leaf: ct.MerkleTreeLeaf{Version: ct.V1, LeafType: ct.TimestampedEntryLeafType},
	}
	switch leaf.entryType {
	case 0:
		rle.Leaf.TimestampedEntry = &ct.TimestampedEntry{
			Timestamp: leaf.timestamp,
			EntryType: ct.X509LogEntryType,
			X509Entry: &ct.ASN1Cert{Data: leaf.x509Entry},
		}
		rle.Cert = ct.ASN1Cert{Data: leaf.x509Entry}
	case 1:
		rle.Leaf.TimestampedEntry = &ct.TimestampedEntry{
			Timestamp: leaf.timestamp,
			EntryType: ct.PrecertLogEntryType,
			PrecertEntry: &ct.PreCert{
				IssuerKeyHash:  leaf.issuerKeyHash,
				TBSCertificate: leaf.precertEntry,
			},
		}
	}
	return rle
}
