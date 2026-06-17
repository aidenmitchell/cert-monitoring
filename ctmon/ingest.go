package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/coder/websocket"
)

// wsMessage is the certstream lite-stream payload (metadata only).
type wsMessage struct {
	MessageType string `json:"message_type"`
	Data        struct {
		CertIndex  uint64  `json:"cert_index"`
		Seen       float64 `json:"seen"`
		UpdateType string  `json:"update_type"`
		LeafCert   struct {
			AllDomains         []string `json:"all_domains"`
			SHA256             string   `json:"sha256"`
			NotBefore          int64    `json:"not_before"`
			NotAfter           int64    `json:"not_after"`
			SignatureAlgorithm string   `json:"signature_algorithm"`
			IsCA               bool     `json:"is_ca"`
			Subject            struct {
				CN string `json:"CN"`
				O  string `json:"O"`
			} `json:"subject"`
			Issuer struct {
				CN string `json:"CN"`
				O  string `json:"O"`
			} `json:"issuer"`
		} `json:"leaf_cert"`
		Source struct {
			Name string `json:"name"`
			URL  string `json:"url"`
			Type string `json:"type"`
		} `json:"source"`
	} `json:"data"`
}

// decodeHashHex turns certstream's "AA:BB:.." colon-hex into 32 raw bytes,
// zero-padding on any malformed input rather than dropping the row.
func decodeHashHex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, ":", ""))
	if err != nil || len(b) != 32 {
		out := make([]byte, 32)
		copy(out, b)
		return out
	}
	return b
}

func rowFromMessage(m *wsMessage) (certRow, bool) {
	if m.MessageType != "certificate_update" {
		return certRow{}, false
	}
	d, lc := &m.Data, &m.Data.LeafCert
	var isCA uint8
	if lc.IsCA {
		isCA = 1
	}
	updateType := d.UpdateType
	if updateType == "" {
		updateType = "X509LogEntry"
	}
	return certRow{
		sha256:             decodeHashHex(lc.SHA256),
		seen:               time.UnixMilli(int64(d.Seen * 1000)).UTC(),
		notBefore:          time.Unix(lc.NotBefore, 0).UTC(),
		notAfter:           time.Unix(lc.NotAfter, 0).UTC(),
		allDomains:         lc.AllDomains, // certstream already appends CN
		subjectCN:          lc.Subject.CN,
		subjectO:           lc.Subject.O,
		issuerCN:           lc.Issuer.CN,
		issuerO:            lc.Issuer.O,
		signatureAlgorithm: lc.SignatureAlgorithm,
		isCA:               isCA,
		updateType:         updateType,
		sourceName:         d.Source.Name,
		sourceURL:          d.Source.URL,
		sourceType:         d.Source.Type,
		certIndex:          d.CertIndex,
	}, true
}

// batcher decouples the WebSocket reader from ClickHouse: add() only does a
// quick lock-append (never I/O), while a single inserter goroutine owns all
// writes. This is critical — if the reader blocked on inserts, it would stop
// draining the socket and certstream would silently drop messages (creating
// gaps across every log at once).
type batcher struct {
	conn   driver.Conn
	cfg    config
	mu     sync.Mutex
	rows   []certRow
	notify chan struct{} // nudges the inserter when the buffer hits batchSize
}

func newBatcher(conn driver.Conn, cfg config) *batcher {
	return &batcher{conn: conn, cfg: cfg, notify: make(chan struct{}, 1)}
}

func (b *batcher) add(r certRow) {
	b.mu.Lock()
	b.rows = append(b.rows, r)
	n := len(b.rows)
	b.mu.Unlock()
	if n >= b.cfg.batchSize {
		select {
		case b.notify <- struct{}{}:
		default: // a nudge is already queued
		}
	}
}

func (b *batcher) takeRows() []certRow {
	b.mu.Lock()
	defer b.mu.Unlock()
	batch := b.rows
	b.rows = nil
	return batch
}

// runInserter owns every ClickHouse write. On failure it keeps the rows in
// `pending` and retries next tick (a ClickHouse blip is a delay, not loss);
// only past maxBuffer does it drop the oldest, loudly — a gap the backfiller
// then repairs. The WS reader is never blocked by any of this.
func (b *batcher) runInserter(ctx context.Context) {
	t := time.NewTicker(b.cfg.batchInterval)
	defer t.Stop()
	var pending []certRow

	flush := func() {
		pending = append(pending, b.takeRows()...)
		if len(pending) == 0 {
			return
		}
		ic, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := insertRows(ic, b.conn, pending)
		cancel()
		if err != nil {
			log.Printf("insert failed (%v); buffered %d rows for retry", err, len(pending))
			if len(pending) > b.cfg.maxBuffer {
				drop := len(pending) - b.cfg.maxBuffer
				pending = append([]certRow(nil), pending[drop:]...)
				log.Printf("ERROR buffer exceeded %d; dropped %d oldest rows (gap detection will flag this)",
					b.cfg.maxBuffer, drop)
			}
			return
		}
		log.Printf("inserted %d rows", len(pending))
		pending = pending[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush() // final
			return
		case <-t.C:
			flush()
		case <-b.notify:
			flush()
		}
	}
}

func runIngest(ctx context.Context, cfg config, conn driver.Conn) {
	b := newBatcher(conn, cfg)
	done := make(chan struct{})
	go func() { b.runInserter(ctx); close(done) }()

	backoff := time.Second
	for ctx.Err() == nil {
		err := consume(ctx, cfg, b)
		if ctx.Err() != nil {
			break
		}
		log.Printf("ws error: %v — reconnecting in %s", err, backoff)
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
	<-done // let the inserter finish its final flush
}

func consume(ctx context.Context, cfg config, b *batcher) error {
	c, _, err := websocket.Dial(ctx, cfg.wsURL, nil)
	if err != nil {
		return err
	}
	defer c.CloseNow()
	c.SetReadLimit(32 << 20)
	log.Printf("connected to certstream at %s", cfg.wsURL)

	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return err
		}
		var m wsMessage
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		if r, ok := rowFromMessage(&m); ok {
			b.add(r)
		}
	}
}
