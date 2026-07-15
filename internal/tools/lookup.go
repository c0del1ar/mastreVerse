package tools

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"mastreverse/internal/core"
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
	r, err := core.Hc.Get(core.ShodanURL + ip)
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
	req, _ := http.NewRequest("GET", core.BgpHEBaseURL+ip, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
	r, err := core.Hc.Do(req)
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
	r, err := core.Hc.Get(core.HackertargetURL + ip)
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

// ── RapidDNS (HTML scrape) ──────────────────────

func rapidDNSLookup(ip string) []string {
	req, _ := http.NewRequest("GET", core.RapidDNSURL+ip+"?full=1", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
	r, err := core.Hc.Do(req)
	if err != nil || r.StatusCode != 200 {
		return nil
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	// domains sit in <td>domain.tld</td> cells
	re := regexp.MustCompile(`<td>([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})</td>`)
	ms := re.FindAllStringSubmatch(string(body), -1)
	seen := map[string]bool{}
	var out []string
	for _, m := range ms {
		d := strings.ToLower(m[1])
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// ── Google DNS-over-HTTPS (PTR) ─────────────────

func reverseIPArpa(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ".in-addr.arpa"
}

type dohResponse struct {
	Answer []struct {
		Data string `json:"data"`
	} `json:"Answer"`
}

func googleDoHLookup(ip string) []string {
	arpa := reverseIPArpa(ip)
	if arpa == "" {
		return nil
	}
	r, err := core.Hc.Get(core.GoogleDoHURL + "?name=" + arpa + "&type=PTR")
	if err != nil || r.StatusCode != 200 {
		return nil
	}
	defer r.Body.Close()
	var resp dohResponse
	json.NewDecoder(r.Body).Decode(&resp)
	var out []string
	for _, a := range resp.Answer {
		d := strings.TrimSuffix(a.Data, ".")
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

// ── Cloudflare DNS-over-HTTPS (PTR) ─────────────

func cloudflareDoHLookup(ip string) []string {
	arpa := reverseIPArpa(ip)
	if arpa == "" {
		return nil
	}
	req, _ := http.NewRequest("GET", core.CloudflareDoHURL+"?name="+arpa+"&type=PTR", nil)
	req.Header.Set("Accept", "application/dns-json")
	r, err := core.Hc.Do(req)
	if err != nil || r.StatusCode != 200 {
		return nil
	}
	defer r.Body.Close()
	var resp dohResponse
	json.NewDecoder(r.Body).Decode(&resp)
	var out []string
	for _, a := range resp.Answer {
		d := strings.TrimSuffix(a.Data, ".")
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

// ── Aggregator ──────────────────────────────────

func LookupAll(target string, opts core.Options) core.Result {
	t0 := time.Now()
	ip, err := resolveIP(target)
	if err != nil {
		return core.Result{Target: target, Err: fmt.Errorf("resolve: %w", err), Elapsed: time.Since(t0)}
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
	if opts.RapidDNS {
		add(rapidDNSLookup(ip))
	}
	if opts.GoogleDoH {
		add(googleDoHLookup(ip))
	}
	if opts.CloudflareDoH {
		add(cloudflareDoHLookup(ip))
	}
	sort.Strings(domains)
	return core.Result{Target: target, IP: ip, Domains: domains, Elapsed: time.Since(t0)}
}
