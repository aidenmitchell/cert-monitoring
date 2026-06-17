// ctmon is the single data-plane service for the CT monitoring stack.
//
//	ctmon seed   — one-shot: write each CT log's current tip to ct_index.json
//	               (so certstream's recovery resumes from "now", not index 0).
//	ctmon        — run mode: concurrently ingest the certstream lite WebSocket
//	               into ClickHouse AND detect/repair gaps via direct CT fetches.
//
// Ingest and backfill share one certRow struct, one insert path, and one schema
// contract (clickhouse.go) so streamed and backfilled rows can never drift.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type config struct {
	chAddr, chUser, chPass, chDB string
	wsURL                        string
	batchSize                    int
	batchInterval                time.Duration
	maxBuffer                    int
	backfillInterval             time.Duration
	maxGap                       uint64
	rfcChunk                     int
	backfillConcurrency          int
	backfillRetries              int
	ctIndexFile                  string
	seedTimeout                  time.Duration
	seedWorkers                  int
	seedRetries                  int
}

func loadConfig() config {
	return config{
		chAddr:              env("CLICKHOUSE_HOST", "clickhouse") + ":" + env("CLICKHOUSE_PORT", "9000"),
		chUser:              env("CLICKHOUSE_USER", "default"),
		chPass:              env("CLICKHOUSE_PASSWORD", ""),
		chDB:                env("CLICKHOUSE_DB", "ct"),
		wsURL:               env("CERTSTREAM_WS_URL", "ws://certstream:8080/"),
		batchSize:           envInt("BATCH_SIZE", 50000),
		batchInterval:       time.Duration(envInt("BATCH_SECONDS", 5)) * time.Second,
		maxBuffer:           envInt("MAX_BUFFER", 500000),
		backfillInterval:    envDuration("BACKFILL_INTERVAL", time.Hour),
		maxGap:              uint64(envInt("MAX_GAP", 100000)),
		rfcChunk:            envInt("RFC_CHUNK", 256),
		backfillConcurrency: envInt("BACKFILL_CONCURRENCY", 6),
		backfillRetries:     envInt("BACKFILL_RETRIES", 6),
		ctIndexFile:         env("CT_INDEX_FILE", "/state/ct_index.json"),
		seedTimeout:         time.Duration(envInt("SEED_TIMEOUT", 15)) * time.Second,
		seedWorkers:         envInt("SEED_WORKERS", 12),
		seedRetries:         envInt("SEED_RETRIES", 5),
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg := loadConfig()

	if len(os.Args) > 1 && os.Args[1] == "seed" {
		if err := runSeed(cfg); err != nil {
			log.Fatalf("seed: %v", err)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	conn, err := connectCH(cfg)
	if err != nil {
		log.Fatalf("clickhouse open: %v", err)
	}
	defer conn.Close()
	log.Printf("ctmon up; clickhouse=%s db=%s ws=%s backfill_interval=%s max_gap=%d",
		cfg.chAddr, cfg.chDB, cfg.wsURL, cfg.backfillInterval, cfg.maxGap)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); runIngest(ctx, cfg, conn) }()
	go func() { defer wg.Done(); runBackfillLoop(ctx, cfg, conn) }()
	wg.Wait()
	log.Println("shutdown complete")
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
