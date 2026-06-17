// webui serves a small domain-lookup tool over the CT data: enter a domain,
// optionally include subdomains, and get certificate stats out of ClickHouse.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

//go:embed index.html
var indexHTML []byte

var conn driver.Conn

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	var err error
	conn, err = clickhouse.Open(&clickhouse.Options{
		Addr: []string{env("CLICKHOUSE_HOST", "clickhouse") + ":" + env("CLICKHOUSE_PORT", "9000")},
		Auth: clickhouse.Auth{
			Database: env("CLICKHOUSE_DB", "ct"),
			Username: env("CLICKHOUSE_USER", "default"),
			Password: env("CLICKHOUSE_PASSWORD", ""),
		},
	})
	if err != nil {
		log.Fatalf("clickhouse open: %v", err)
	}
	defer conn.Close()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	http.HandleFunc("/api/lookup", lookupHandler)

	addr := env("LISTEN_ADDR", ":8088")
	log.Printf("webui listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// normalizeDomain lowercases and strips anything that isn't the hostname
// (scheme, path, a leading wildcard, trailing dot).
func normalizeDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s = strings.TrimPrefix(s, "*.")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return strings.Trim(s, ".")
}

func reverseDomain(d string) string {
	p := strings.Split(d, ".")
	for i, j := 0, len(p)-1; i < j; i, j = i+1, j-1 {
		p[i], p[j] = p[j], p[i]
	}
	return strings.Join(p, ".")
}

type issuer struct {
	Name  string `json:"name"`
	Certs uint64 `json:"certs"`
}

type certRow struct {
	Domain    string `json:"domain"`
	Issuer    string `json:"issuer"`
	NotBefore int64  `json:"not_before"`
	NotAfter  int64  `json:"not_after"`
	Seen      int64  `json:"seen"`
}

type response struct {
	Domain     string    `json:"domain"`
	Subdomains bool      `json:"subdomains"`
	Found      bool      `json:"found"`
	Certs      uint64    `json:"certs"`
	Active     uint64    `json:"active"`
	Domains    uint64    `json:"domains"`
	FirstSeen  int64     `json:"first_seen"`
	LastSeen   int64     `json:"last_seen"`
	Issuers    []issuer  `json:"issuers"`
	Recent     []certRow `json:"recent"`
	Error      string    `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func lookupHandler(w http.ResponseWriter, r *http.Request) {
	domain := normalizeDomain(r.URL.Query().Get("domain"))
	subdomains := r.URL.Query().Get("subdomains") == "true"
	if domain == "" || !strings.Contains(domain, ".") {
		writeJSON(w, http.StatusBadRequest, response{Error: "Enter a valid domain, e.g. example.com"})
		return
	}

	rev := reverseDomain(domain)
	scope := "reversed_domain = {rev:String}"
	args := []any{clickhouse.Named("rev", rev)}
	if subdomains {
		scope = "(reversed_domain = {rev:String} OR reversed_domain LIKE {pfx:String})"
		args = append(args, clickhouse.Named("pfx", rev+".%"))
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	resp := response{Domain: domain, Subdomains: subdomains}

	// Summary
	var firstSeen, lastSeen time.Time
	row := conn.QueryRow(ctx,
		"SELECT uniqExact(sha256), uniqExactIf(sha256, not_after >= now()), uniqExact(domain), "+
			"min(seen), max(seen) FROM domain_certs WHERE "+scope, args...)
	if err := row.Scan(&resp.Certs, &resp.Active, &resp.Domains, &firstSeen, &lastSeen); err != nil {
		log.Printf("summary query: %v", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "Query failed"})
		return
	}
	if resp.Certs == 0 {
		writeJSON(w, http.StatusOK, resp) // Found=false
		return
	}
	resp.Found = true
	resp.FirstSeen = firstSeen.Unix()
	resp.LastSeen = lastSeen.Unix()

	// Top issuers
	if rows, err := conn.Query(ctx,
		"SELECT issuer_o, uniqExact(sha256) AS c FROM domain_certs WHERE "+scope+
			" AND issuer_o != '' GROUP BY issuer_o ORDER BY c DESC LIMIT 8", args...); err == nil {
		for rows.Next() {
			var is issuer
			if rows.Scan(&is.Name, &is.Certs) == nil {
				resp.Issuers = append(resp.Issuers, is)
			}
		}
		rows.Close()
	}

	// Recent certificates
	if rows, err := conn.Query(ctx,
		"SELECT domain, issuer_o, not_before, not_after, seen FROM domain_certs WHERE "+scope+
			" ORDER BY seen DESC LIMIT 30", args...); err == nil {
		for rows.Next() {
			var c certRow
			var nb, na, sn time.Time
			if rows.Scan(&c.Domain, &c.Issuer, &nb, &na, &sn) == nil {
				c.NotBefore, c.NotAfter, c.Seen = nb.Unix(), na.Unix(), sn.Unix()
				resp.Recent = append(resp.Recent, c)
			}
		}
		rows.Close()
	}

	writeJSON(w, http.StatusOK, resp)
}
