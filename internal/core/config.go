package core

import (
	"bufio"
	"net/http"
	"time"
)

const MaxThreads = 50

const (
	Rst     = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	itl     = "\033[3m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[97m"
	bgBlue  = "\033[44m"
	bgDark  = "\033[40m"

	WhatsmyipURL     = "https://api.mxtoolbox.com/api/v1/utils/whatsmyip"
	ShodanURL        = "https://internetdb.shodan.io/"
	BgpHEBaseURL     = "https://bgp.he.net/ip/"
	HackertargetURL  = "https://api.hackertarget.com/reverseiplookup/?q="
	RapidDNSURL      = "https://rapiddns.io/sameip/"
	GoogleDoHURL     = "https://dns.google/resolve"
	CloudflareDoHURL = "https://cloudflare-dns.com/dns-query"
)

var Hc = &http.Client{Timeout: 15 * time.Second}
var Version = "v1.1.0"

// shared stdin reader (created after raw-mode UI exits)
var Rd *bufio.Reader

// ══════════════════════════════════════════════════
//  TYPES
// ══════════════════════════════════════════════════

type srcDef struct {
	Name      string
	Short     string
	Enabled   bool
	RateLabel string
}

var Srcs = []srcDef{
	{"DNS PTR", "ptr", true, "unlimited"},
	{"Shodan InternetDB", "shodan", true, "unlimited"},
	{"bgp.he.net", "bgphe", true, "unlimited"},
	{"hackertarget.com", "ht", true, "! ~5/day"},
	{"RapidDNS", "rapiddns", true, "unlimited"},
	{"Google DoH", "gdoh", true, "unlimited"},
	{"Cloudflare DoH", "cfdoh", true, "unlimited"},
}

type Options struct {
	PTR, Shodan, BGPHE, HT             bool
	RapidDNS, GoogleDoH, CloudflareDoH bool
}

type Result struct {
	Target  string
	IP      string
	Domains []string
	Err     error
	Elapsed time.Duration
}

type Msg struct{ Kind, Text string }
