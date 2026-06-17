package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const logListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

// logList is the subset of Google's v3 log list we need: RFC6962 logs (url) and
// tiled logs (monitoring_url).
type logList struct {
	Operators []struct {
		Logs []struct {
			Description string `json:"description"`
			URL         string `json:"url"`
		} `json:"logs"`
		TiledLogs []struct {
			Description   string `json:"description"`
			MonitoringURL string `json:"monitoring_url"`
		} `json:"tiled_logs"`
	} `json:"operators"`
}

type seedTarget struct {
	key, desc string
	fetch     func(context.Context) (uint64, error)
}

// runSeed writes each log's current tip into ct_index.json so certstream's
// recovery resumes from "now". Merge semantics + 429 retries make it
// self-healing: re-running only fills logs missing from the file.
func runSeed(cfg config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	index := map[string]uint64{}
	if data, err := os.ReadFile(cfg.ctIndexFile); err == nil {
		_ = json.Unmarshal(data, &index)
	}

	log.Printf("[seed] fetching log list: %s", logListURL)
	ll, err := fetchLogList(ctx, cfg)
	if err != nil {
		return fmt.Errorf("fetch log list: %w", err)
	}

	var todo []seedTarget
	for _, t := range collectTargets(ll) {
		if _, ok := index[t.key]; !ok {
			todo = append(todo, t)
		}
	}
	if len(todo) == 0 {
		log.Printf("[seed] all %d logs already seeded — nothing to do.", len(index))
		return nil
	}
	log.Printf("[seed] %d already seeded; querying tip of %d new logs ...", len(index), len(todo))

	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		failed int
		sem    = make(chan struct{}, cfg.seedWorkers)
	)
	for _, t := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func(t seedTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			tip, err := t.fetch(ctx)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
				log.Printf("[seed]   skip %s: %v", t.desc, err)
				return
			}
			index[t.key] = tip
		}(t)
	}
	wg.Wait()

	if err := writeIndex(cfg.ctIndexFile, index); err != nil {
		return err
	}
	log.Printf("[seed] wrote %d log tips to %s (%d newly seeded, %d failed/skipped).",
		len(index), cfg.ctIndexFile, len(todo)-failed, failed)
	return nil
}

func collectTargets(ll *logList) []seedTarget {
	var targets []seedTarget
	for _, op := range ll.Operators {
		for _, lg := range op.Logs {
			if lg.URL == "" {
				continue
			}
			url := lg.URL
			targets = append(targets, seedTarget{
				key: normalizeURL(url), desc: lg.Description,
				fetch: func(ctx context.Context) (uint64, error) { return rfc6962Tip(ctx, url) },
			})
		}
		for _, lg := range op.TiledLogs {
			if lg.MonitoringURL == "" {
				continue
			}
			url := lg.MonitoringURL
			targets = append(targets, seedTarget{
				key: normalizeURL(url), desc: lg.Description,
				fetch: func(ctx context.Context) (uint64, error) {
					var s uint64
					err := withRetry(ctx, 5, "checkpoint "+url, func() error {
						v, e := fetchCheckpointSize(ctx, url)
						if e != nil {
							return e
						}
						s = v
						return nil
					})
					return s, err
				},
			})
		}
	}
	return targets
}

func rfc6962Tip(ctx context.Context, base string) (uint64, error) {
	data, status, err := seedGet(ctx, strings.TrimRight(base, "/")+"/ct/v1/get-sth")
	if err != nil || status != http.StatusOK {
		return 0, fmt.Errorf("get-sth status %d err %v", status, err)
	}
	var sth struct {
		TreeSize uint64 `json:"tree_size"`
	}
	if err := json.Unmarshal(data, &sth); err != nil {
		return 0, err
	}
	return sth.TreeSize, nil
}

func fetchLogList(ctx context.Context, cfg config) (*logList, error) {
	data, status, err := seedGet(ctx, logListURL)
	if err != nil || status != http.StatusOK {
		return nil, fmt.Errorf("status %d err %v", status, err)
	}
	var ll logList
	if err := json.Unmarshal(data, &ll); err != nil {
		return nil, err
	}
	return &ll, nil
}

// seedGet retries 429s (Retry-After may be seconds or an HTTP-date we ignore in
// favor of backoff) and transient errors, so rate-limited logs still get seeded.
func seedGet(ctx context.Context, url string) ([]byte, int, error) {
	const retries = 5
	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		body, status, retryAfter, err := httpGet(ctx, url)
		switch {
		case err == nil && status == http.StatusOK:
			return body, status, nil
		case status == http.StatusTooManyRequests:
			wait := backoffDur(attempt)
			if retryAfter > 0 {
				wait = retryAfter
			}
			time.Sleep(wait)
		case err != nil:
			if nonRetryable(err) {
				return nil, 0, err // e.g. DNS NXDOMAIN — don't retry retired/bogus logs
			}
			lastErr = err
			time.Sleep(backoffDur(attempt))
		default:
			return nil, status, nil // non-retryable non-200
		}
	}
	return nil, 0, fmt.Errorf("exhausted retries: %v", lastErr)
}

// backoffDur is capped exponential backoff with jitter (50%-100% of the target)
// so concurrent retries against a rate-limiting log don't synchronize.
func backoffDur(attempt int) time.Duration {
	d := time.Duration(1<<uint(attempt)) * time.Second
	if d > 60*time.Second {
		d = 60 * time.Second
	}
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

// writeIndex writes the map atomically and relaxes permissions so certstream
// (uid 10001) can rewrite the file + its .tmp on every 30s checkpoint.
func writeIndex(path string, index map[string]uint64) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	data, err := json.MarshalIndent(index, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".seedtmp"
	if err := os.WriteFile(tmp, data, 0o666); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	_ = os.Chmod(filepath.Dir(path), 0o777)
	_ = os.Chmod(path, 0o666)
	return nil
}
