package main

import (
	"context"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// certRow is THE shared row contract. Both the ingester (from certstream JSON)
// and the backfiller (from raw CT entries) build this struct, and insertRows is
// the single place that knows the certs/cert_sightings column layout — so the
// two producers cannot drift from each other or from the schema.
type certRow struct {
	sha256                            []byte // FixedString(32)
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

func connectCH(cfg config) (driver.Conn, error) {
	return clickhouse.Open(&clickhouse.Options{
		Addr: []string{cfg.chAddr},
		Auth: clickhouse.Auth{Database: cfg.chDB, Username: cfg.chUser, Password: cfg.chPass},
	})
}

// insertRows writes to cert_sightings then certs. Ledger first so that if the
// certs insert fails and the caller retries, the re-inserted ledger rows just
// dedup (ReplacingMergeTree on source_url+cert_index). The materialized view
// repopulates domain_certs from the certs insert automatically.
func insertRows(ctx context.Context, conn driver.Conn, rows []certRow) error {
	sb, err := conn.PrepareBatch(ctx, "INSERT INTO cert_sightings")
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := sb.Append(r.sourceURL, r.sourceType, r.certIndex, r.seen); err != nil {
			return err
		}
	}
	if err := sb.Send(); err != nil {
		return err
	}

	cb, err := conn.PrepareBatch(ctx, "INSERT INTO certs")
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := cb.Append(r.sha256, r.seen, r.notBefore, r.notAfter, nonNil(r.allDomains),
			r.subjectCN, r.subjectO, r.issuerCN, r.issuerO, r.signatureAlgorithm,
			r.isCA, r.updateType, r.sourceName, r.sourceURL, r.sourceType, r.certIndex); err != nil {
			return err
		}
	}
	return cb.Send()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
