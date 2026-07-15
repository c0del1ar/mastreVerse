package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

func resolveIP(target string) (string, error) {
	if net.ParseIP(target) != nil {
		return target, nil
	}
	addrs, err := net.LookupHost(target)
	if err != nil {
		return "", err
	}
	return addrs[0], nil
}

func ptrLookup(ip string) []string {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return nil
	}
	for i, n := range names {
		names[i] = strings.TrimSuffix(n, ".")
	}
	return names
}

func shodanLookup(ip string) []string {
	r, err := hc.Get(shodanURL + ip)
	if err != nil || r.StatusCode != 200 {
		return nil
	}
	defer r.Body.Close()
	var d struct {
		Hostnames []string `json:"hostnames"`
	}
	json.NewDecoder(r.Body).Decode(&d)
	return d.Hostnames
}

func bgpHELookup(ip string) []string {
	req, _ := http.NewRequest("GET", bgpHEBaseURL+ip, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
	r, err := hc.Do(req)
	if err != nil {
		return nil
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	re := regexp.MustCompile(`href="/dns/([^"]+)"`)
	ms := re.FindAllStringSubmatch(string(body), -1)
	seen := map[string]bool{}
	var out []string
	for _, m := range ms {
		d := m[1]
		if net.ParseIP(d) != nil || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

func hackertargetLookup(ip string) []string {
	r, err := hc.Get(hackertargetURL + ip)
	if err != nil || r.StatusCode != 200 {
		return nil
	}
	defer r.Body.Close()
	var out []string
	sc := bufio.NewScanner(r.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "error") || strings.HasPrefix(low, "api count") {
			break
		}
		out = append(out, line)
	}
	return out
}

func lookupAll(target string, opts Options) Result {
	t0 := time.Now()
	ip, err := resolveIP(target)
	if err != nil {
		return Result{Target: target, Err: fmt.Errorf("resolve: %w", err), Elapsed: time.Since(t0)}
	}
	seen := map[string]bool{}
	var domains []string
	add := func(items []string) {
		for _, d := range items {
			d = strings.TrimSpace(d)
			if d != "" && !seen[d] {
				seen[d] = true
				domains = append(domains, d)
			}
		}
	}
	if opts.PTR {
		add(ptrLookup(ip))
	}
	if opts.Shodan {
		add(shodanLookup(ip))
	}
	if opts.BGPHE {
		add(bgpHELookup(ip))
	}
	if opts.HT {
		add(hackertargetLookup(ip))
	}
	sort.Strings(domains)
	return Result{Target: target, IP: ip, Domains: domains, Elapsed: time.Since(t0)}
}
