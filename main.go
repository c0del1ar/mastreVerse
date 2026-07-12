package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/term"
)

// ══════════════════════════════════════════════════
//  CONSTANTS & ANSI
// ══════════════════════════════════════════════════

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
	{"DNS PTR", "ptr",    true, "unlimited"},
	{"Shodan InternetDB", "shodan", true, "unlimited"},
	{"bgp.he.net", "bgphe",  true, "unlimited"},
	{"hackertarget.com", "ht",     true, "! ~5/day"},
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

// ══════════════════════════════════════════════════
//  SCREEN & BANNER
// ══════════════════════════════════════════════════

const sepW = 51

func cls() { fmt.Print("\033[2J\033[H") }
func nl()   { fmt.Print("\r\n") }
func sep()  { fmt.Printf("  %s%s%s\r\n", dim, strings.Repeat("-", sepW), rst) }

func banner() {
	fmt.Printf("%s%s\r\n", cyan+bold, "")
	fmt.Print("  ╔╦╗╔═╗╔═╗╔╦╗╦═╗╔═╗  ╦  ╦╔═╗╦═╗╔═╗╔═╗\r\n")
	fmt.Print("  ║║║╠═╣╚═╗ ║ ╠╦╝║╣   ╚╗╔╝║╣ ╠╦╝╚═╗║╣ \r\n")
	fmt.Print("  ╩ ╩╩ ╩╚═╝ ╩ ╩╚═╚═╝   ╚╝ ╚═╝╩╚═╚═╝╚═╝\r\n")
	fmt.Printf("%s", rst)
	fmt.Printf("\r  %sReverse IP Lookup & Blacklist Checker%s\r\n", dim, rst)
	sep()
	nl()
}

// ══════════════════════════════════════════════════
//  MAIN MENU UI (raw terminal)
// ══════════════════════════════════════════════════

func selectTool() int {
	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		if rd == nil { rd = bufio.NewReader(os.Stdin) }
		return 2 // Default to Reverse IP Lookup if not a TTY
	}
	defer term.Restore(fd, state)

	selected := 1
	buf := make([]byte, 4)
	for {
		cls()
		banner()
		
		fmt.Printf("\r  %sMAIN MENU%s\r\n", bold+cyan, rst)
		sep()
		nl()
		
		p1, p2 := " ", " "
		c1, c2 := dim, dim
		if selected == 1 { p1 = ">"; c1 = bold+green }
		if selected == 2 { p2 = ">"; c2 = bold+green }

		fmt.Printf("\r  %s%s%s  Blacklist Checker\r\n", c1, p1, rst)
		fmt.Printf("\r  %s%s%s  Reverse IP Lookup\r\n", c2, p2, rst)

		nl()
		sep()
		fmt.Printf("\r  %sUP/DOWN%s move    %sENTER%s select\r\n", cyan+bold, rst, cyan+bold, rst)
		nl()
		fmt.Printf("\r  %s»%s ", green+bold, rst)

		n, _ := os.Stdin.Read(buf)
		if n == 0 { continue }
		
		if n == 3 && buf[0] == 27 && buf[1] == 91 { // escape sequence
			if buf[2] == 65 { selected = 1 } // UP
			if buf[2] == 66 { selected = 2 } // DOWN
		} else if buf[0] == 0x0d || buf[0] == '\n' {
			return selected
		} else if buf[0] == 0x03 {
			term.Restore(fd, state)
			fmt.Printf("\r\n  %sInterrupted.%s\r\n\r\n", yellow, rst)
			os.Exit(0)
		}
	}
}

// ══════════════════════════════════════════════════
//  CHECKBOX UI  (raw terminal)
// ══════════════════════════════════════════════════

func drawSources() {
	cls()
	banner()

	// Header
	fmt.Printf("\r  %sSELECT SOURCES%s\r\n", bold+cyan, rst)
	sep()
	nl()

	// Entries  — NO right border, no padding math needed
	// [ON ] / [OFF] always exactly 5 visible chars
	for i, s := range srcs {
		var badge string
		if s.Enabled {
			badge = fmt.Sprintf("%s[%sON %s]%s", bold, green, rst+bold, rst)
		} else {
			badge = fmt.Sprintf("%s[%sOFF%s]%s", bold, red, rst+bold, rst)
		}
		fmt.Printf("\r  %s%d%s  %s  %s%-18s%s  %s%s%s\r\n",
			bold+yellow, i+1, rst,
			badge,
			white+bold, s.Name, rst,
			dim, s.RateLabel, rst)
	}

	nl()
	sep()
	fmt.Printf("\r  %s1-4%s toggle    %sa%s all/none    %sENTER%s confirm\r\n",
		cyan+bold, rst, cyan+bold, rst, cyan+bold, rst)
	nl()
	fmt.Printf("\r  %s»%s ", green+bold, rst)
}

func stripANSI(s string) string {
	re := regexp.MustCompile(`\033\[[0-9;]*m`)
	return re.ReplaceAllString(s, "")
}

func selectSources() {
	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		// Not a real TTY — just initialize rd and proceed with defaults (all sources on)
		rd = bufio.NewReader(os.Stdin)
		return
	}
	defer term.Restore(fd, state)

	buf := make([]byte, 4)
	for {
		drawSources()
		n, _ := os.Stdin.Read(buf)
		if n == 0 {
			continue
		}
		ch := buf[0]
		switch {
		case ch == 0x0d || ch == '\n':
			return
		case ch == 0x03: // Ctrl-C
			term.Restore(fd, state)
			fmt.Printf("\n  %sInterrupted.%s\n\n", yellow, rst)
			os.Exit(0)
		case ch == 'a' || ch == 'A':
			allOn := true
			for _, s := range srcs {
				if !s.Enabled {
					allOn = false
					break
				}
			}
			for i := range srcs {
				srcs[i].Enabled = !allOn
			}
		default:
			if ch >= '1' && int(ch-'1') < len(srcs) {
				srcs[ch-'1'].Enabled = !srcs[ch-'1'].Enabled
			}
		}
	}
}


// ══════════════════════════════════════════════════
//  INPUT HELPERS
// ══════════════════════════════════════════════════

func ask(label, hint string) string {
	fmt.Printf("  %s%s%s  %s%s%s\n  %s»%s ",
		bold+cyan, label, rst,
		dim, hint, rst,
		green+bold, rst)
	line, _ := rd.ReadString('\n')
	return strings.TrimFunc(line, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
}

func loadTargets(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		fmt.Printf("  %s[!] Cannot open file: %v%s\n", red+bold, err, rst)
		os.Exit(1)
	}
	defer f.Close()
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t != "" && !strings.HasPrefix(t, "#") && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// ══════════════════════════════════════════════════
//  LOOKUP FUNCTIONS
// ══════════════════════════════════════════════════

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
	if opts.PTR    { add(ptrLookup(ip)) }
	if opts.Shodan { add(shodanLookup(ip)) }
	if opts.BGPHE  { add(bgpHELookup(ip)) }
	if opts.HT     { add(hackertargetLookup(ip)) }
	sort.Strings(domains)
	return Result{Target: target, IP: ip, Domains: domains, Elapsed: time.Since(t0)}
}

// ══════════════════════════════════════════════════
//  OUTPUT FORMATTING
// ══════════════════════════════════════════════════

const previewMax = 6

func fmtResult(r Result, n, total int) string {
	counter := fmt.Sprintf("%s[%s%s%03d/%03d%s%s]%s",
		bold, rst+dim, "", n, total, rst+bold, "", rst)

	if r.Err != nil {
		return fmt.Sprintf(
			"  %s %s✗%s  %s%-20s%s => %s[FAIL] %v%s\n",
			counter, red+bold, rst,
			bold+yellow, r.Target, rst,
			red, r.Err, rst)
	}

	// Target label
	targetLabel := fmt.Sprintf("%s%s%s", bold+yellow, r.IP, rst)
	if r.Target != r.IP {
		targetLabel = fmt.Sprintf("%s%-20s%s%s→%s %s%s%s",
			bold+yellow, r.Target, rst,
			dim, rst,
			bold+cyan, r.IP, rst)
	}

	// Domain list preview
	count := len(r.Domains)
	var domStr string
	if count == 0 {
		domStr = dim + "(no results)" + rst
	} else {
		preview := r.Domains
		more := 0
		if count > previewMax {
			preview = r.Domains[:previewMax]
			more = count - previewMax
		}
		parts := make([]string, len(preview))
		for i, d := range preview {
			parts[i] = white + d + rst
		}
		domStr = strings.Join(parts, dim+", "+rst)
		if more > 0 {
			domStr += fmt.Sprintf(" %s... +%d more%s", dim+yellow, more, rst)
		}
	}

	timing := fmt.Sprintf("%s%.1fs%s", dim, r.Elapsed.Seconds(), rst)

	return fmt.Sprintf(
		"  %s %s✓%s  %s => %s[%s]%s  %s\n",
		counter,
		green+bold, rst,
		targetLabel,
		bold+green, domStr, rst,
		timing)
}

func fmtFile(r Result) string {
	if r.Err != nil || len(r.Domains) == 0 {
		return ""
	}
	return strings.Join(r.Domains, "\n") + "\n"
}

// ══════════════════════════════════════════════════
//  CONCURRENT RUNNER
// ══════════════════════════════════════════════════

func run(targets []string, opts Options, threads int) {
	os.MkdirAll("Result", 0o755)
	outFile, ferr := os.Create("Result/reversed.txt")
	if ferr != nil {
		fmt.Printf("  %s[!] Cannot create output file: %v%s\n", red, ferr, rst)
	} else {
		defer outFile.Close()
	}

	total := int64(len(targets))
	var done int64

	// ── Printer goroutine (single writer to stdout) ──
	pch := make(chan Msg, 1024)
	var prWg sync.WaitGroup
	prWg.Add(1)
	go func() {
		defer prWg.Done()
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		fi := 0
		spinning := false
		for msg := range pch {
			switch msg.Kind {
			case "result":
				if spinning {
					fmt.Print("\r\033[K")
					spinning = false
				}
				fmt.Print(msg.Text)
			case "spin":
				fmt.Printf("\r\033[K  %s%s%s %s",
					cyan+bold, frames[fi%len(frames)], rst, msg.Text)
				fi++
				spinning = true
			case "clear":
				if spinning {
					fmt.Print("\r\033[K")
					spinning = false
				}
			}
		}
	}()

	// ── Spinner ticker ──
	spinStop := make(chan struct{})
	go func() {
		tick := time.NewTicker(80 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				d := atomic.LoadInt64(&done)
				pct := 0
				if total > 0 {
					pct = int(float64(d) / float64(total) * 28)
				}
				bar := green + strings.Repeat("▓", pct) + dim + strings.Repeat("░", 28-pct) + rst
				pch <- Msg{"spin", fmt.Sprintf(
					"%s[%s%s]%s  %s%d/%d%s  scanning...",
					bold+cyan, bar, bold+cyan, rst,
					bold+yellow, d, total, rst,
				)}
			case <-spinStop:
				return
			}
		}
	}()

	// ── Worker pool (semaphore) ──
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	var fileMu sync.Mutex

	for _, target := range targets {
		target := target
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			r := lookupAll(target, opts)
			n := int(atomic.AddInt64(&done, 1))

			pch <- Msg{"result", fmtResult(r, n, int(total))}

			if outFile != nil {
				fileMu.Lock()
				fmt.Fprint(outFile, fmtFile(r))
				fileMu.Unlock()
			}
		}()
	}

	wg.Wait()
	close(spinStop)
	pch <- Msg{"clear", ""}
	close(pch)
	prWg.Wait()
}

// ══════════════════════════════════════════════════
//  MAIN
// ══════════════════════════════════════════════════

func main() {
	tool := selectTool()
	
	if rd == nil {
		rd = bufio.NewReader(os.Stdin)
	}

	if tool == 1 {
		runBlacklistMenu()
		return
	}

	runReverseIPLookup()
}

func runBlacklistMenu() {
	cls()
	banner()
	fmt.Printf("  %sBLACKLIST CHECKER%s\n", bold+cyan, rst)
	sep()
	fmt.Printf("  %scheck IP or domain against 100+ blacklists%s\n\n", dim, rst)
	
	target := ask("Target", "e.g. 8.8.8.8  or  example.com")
	if target == "" {
		fmt.Printf("\n  %s[!] No target provided.%s\n\n", red, rst)
		os.Exit(1)
	}
	
	blacklistCheck(target)
}

func runReverseIPLookup() {
	cls()
	banner()

	// ── Connectivity check ──
	fmt.Printf("  %s[~]%s Checking connectivity...", yellow+bold, rst)
	resp, err := hc.Get(whatsmyipURL)
	if err != nil {
		fmt.Printf("  %s[ERR] No internet. Check connection.%s\n\n", red+bold, rst)
		os.Exit(1)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var myIP string
	json.Unmarshal(body, &myIP)
	fmt.Printf(" %s[OK]%s  outbound IP: %s%s%s\n\n", green+bold, rst, bold+cyan, myIP, rst)

	// ── Source selection (raw terminal mode) ──
	selectSources()

	// ── Build opts ──
	opts := Options{}
	anyOn := false
	for _, s := range srcs {
		if s.Enabled { anyOn = true }
		switch s.Short {
		case "ptr":    opts.PTR    = s.Enabled
		case "shodan": opts.Shodan = s.Enabled
		case "bgphe":  opts.BGPHE  = s.Enabled
		case "ht":     opts.HT     = s.Enabled
		}
	}
	if !anyOn {
		fmt.Printf("\n  %s[!] No sources selected.%s\n\n", red, rst)
		os.Exit(1)
	}

	// ── Switch to cooked mode ──
	if rd == nil {
		rd = bufio.NewReader(os.Stdin)
	}

	cls()
	banner()

	// ── File input ──
	fmt.Printf("  %sTARGET FILE%s\n", bold+cyan, rst)
	sep()
	fmt.Printf("  %sone IP or domain per line · lines starting with # are skipped%s\n\n", dim, rst)

	filePath := ask("path", "e.g.  targets.txt   /home/user/ips.txt")
	if filePath == "" {
		fmt.Printf("\n  %s[!] No file provided.%s\n\n", red, rst)
		os.Exit(1)
	}
	targets := loadTargets(filePath)
	if len(targets) == 0 {
		fmt.Printf("\n  %s[!] File is empty or not found.%s\n\n", red, rst)
		os.Exit(1)
	}
	fmt.Printf("\n  %s[+]%s %s%d%s targets loaded\n\n", green+bold, rst, bold+yellow, len(targets), rst)

	// ── Thread input ──
	fmt.Printf("  %sTHREADS%s\n", bold+cyan, rst)
	sep()
	fmt.Printf("  %smax %d · default 10%s\n\n", dim, maxThreads, rst)

	threadStr := ask("count", fmt.Sprintf("1-%d", maxThreads))
	threads := 10
	if n, err := strconv.Atoi(threadStr); err == nil && n >= 1 {
		if n > maxThreads { n = maxThreads }
		threads = n
	}

	// ── Config summary ──
	srcList := []string{}
	if opts.PTR    { srcList = append(srcList, "PTR") }
	if opts.Shodan { srcList = append(srcList, "Shodan") }
	if opts.BGPHE  { srcList = append(srcList, "bgp.he.net") }
	if opts.HT     { srcList = append(srcList, "hackertarget") }

	nl()
	fmt.Printf("  %sREADY%s\n", bold+cyan, rst)
	sep()
	fmt.Printf("  %-10s  %s%s%s\n", "sources", green, strings.Join(srcList, "  "), rst)
	fmt.Printf("  %-10s  %s%d%s entries\n", "targets", bold+yellow, len(targets), rst)
	fmt.Printf("  %-10s  %s%d%s workers\n", "threads", bold+yellow, threads, rst)
	fmt.Printf("  %-10s  %sResult/reversed.txt%s\n", "output", cyan, rst)
	sep()
	nl()

	// ── Confirm ──
	fmt.Printf("  %s[Y/n]%s  Start scan? » ", green+bold, rst)
	ans, _ := rd.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))
	if ans == "n" || ans == "no" {
		fmt.Printf("\n  %sAborted.%s\n\n", yellow, rst)
		return
	}

	// ── Run ──
	nl()
	fmt.Printf("  %sSCANNING%s  %s%d targets  //  %d threads%s\n", bold+green, rst, dim, len(targets), threads, rst)
	sep()
	nl()

	t0 := time.Now()
	run(targets, opts, threads)
	elapsed := time.Since(t0)

	// ── Done ──
	nl()
	fmt.Printf("  %sDONE%s\n", bold+green, rst)
	sep()
	fmt.Printf("  %d targets  //  %.2fs elapsed\n", len(targets), elapsed.Seconds())
	fmt.Printf("  %sresults  ->  Result/reversed.txt%s\n", cyan, rst)
	sep()
	nl()
}
