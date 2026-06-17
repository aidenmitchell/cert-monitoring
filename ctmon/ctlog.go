package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/crypto/cryptobyte"
)

const (
	userAgent = "cert-monitoring-ctmon/1.0"
	tileSize  = 256
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// normalizeURL matches certstream's normalizeCtlogURL so our index/source keys
// line up exactly: strip scheme and trailing slash, no lowercasing.
func normalizeURL(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	return strings.TrimRight(u, "/")
}

// fetchErr carries the HTTP status and any Retry-After hint so the retry layer
// can honor the log's guidance and skip non-retryable statuses (e.g. 403).
type fetchErr struct {
	status     int
	retryAfter time.Duration
}

func (e *fetchErr) Error() string { return fmt.Sprintf("HTTP %d", e.status) }

// retryableStatus: transient statuses worth retrying. 4xx (other than 408/429)
// are hard errors — retrying just hammers the log.
func retryableStatus(s int) bool { return s == 408 || s == 429 || s >= 500 }

// parseRetryAfter handles both forms of the Retry-After header: delta-seconds
// and an HTTP-date.
func parseRetryAfter(h string) time.Duration {
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// httpGet returns (body, statusCode, retryAfter, err). A non-200 yields a nil
// body and the status code with no error, so callers can branch on 404 etc.
func httpGet(ctx context.Context, url string) ([]byte, int, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, 0, err
	}
	defer resp.Body.Close()
	ra := parseRetryAfter(resp.Header.Get("Retry-After"))
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, ra, nil
	}
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, ra, err
}

func fetchCheckpointSize(ctx context.Context, base string) (uint64, error) {
	data, status, ra, err := httpGet(ctx, strings.TrimRight(base, "/")+"/checkpoint")
	if err != nil {
		return 0, err
	}
	if status != http.StatusOK {
		// fetchErr so callers' retry honors Retry-After / 429 and fails fast on 4xx.
		return 0, &fetchErr{status: status, retryAfter: ra}
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("bad checkpoint")
	}
	return strconv.ParseUint(strings.TrimSpace(lines[1]), 10, 64)
}

// --- tiled (static-ct-api) tile fetch + parse, ported from certstream-server-go.

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

// fetchTile fetches a data tile. width==0 fetches the full, immutable tile
// (/tile/data/<path>); width>0 fetches the partial tile at that width
// (/tile/data/<path>.p/<width>) per the static-ct-api spec. S3-backed logs
// return 403 (not 404) for a not-yet-written full tile, so callers must request
// the partial tile explicitly rather than relying on a 404 fallback.
func fetchTile(ctx context.Context, base string, tileIndex, width uint64) ([]tileLeaf, error) {
	path := fmt.Sprintf("%s/tile/data/%s", base, encodeTilePath(tileIndex))
	if width > 0 {
		path = fmt.Sprintf("%s.p/%d", path, width)
	}
	data, status, ra, err := httpGet(ctx, path)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &fetchErr{status: status, retryAfter: ra}
	}
	return parseTileData(data)
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
		Leaf:  ct.MerkleTreeLeaf{Version: ct.V1, LeafType: ct.TimestampedEntryLeafType},
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
