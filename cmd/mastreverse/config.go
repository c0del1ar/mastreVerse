package main

import (
	"bufio"
	"net/http"
	"time"
)

const maxThreads = 50

const (
	rst     = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	itl     = "\033[3m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	white   = "\033[97m"
	bgBlue  = "\033[44m"
	bgDark  = "\033[40m"

	whatsmyipURL    = "https://api.mxtoolbox.com/api/v1/utils/whatsmyip"
	shodanURL       = "https://internetdb.shodan.io/"
	bgpHEBaseURL    = "https://bgp.he.net/ip/"
	hackertargetURL = "https://api.hackertarget.com/reverseiplookup/?q="
)

var hc = &http.Client{Timeout: 15 * time.Second}

// shared stdin reader (created after raw-mode UI exits)
var rd *bufio.Reader

// ══════════════════════════════════════════════════
//  TYPES
// ══════════════════════════════════════════════════

type srcDef struct {
	Name      string
	Short     string
	Enabled   bool
	RateLabel string
}

var srcs = []srcDef{
	{"DNS PTR", "ptr", true, "unlimited"},
	{"Shodan InternetDB", "shodan", true, "unlimited"},
	{"bgp.he.net", "bgphe", true, "unlimited"},
	{"hackertarget.com", "ht", true, "! ~5/day"},
}

type Options struct{ PTR, Shodan, BGPHE, HT bool }

type Result struct {
	Target  string
	IP      string
	Domains []string
	Err     error
	Elapsed time.Duration
}

type Msg struct{ Kind, Text string }
