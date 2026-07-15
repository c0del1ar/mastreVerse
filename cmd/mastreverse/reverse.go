package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

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
		if s.Enabled {
			anyOn = true
		}
		switch s.Short {
		case "ptr":
			opts.PTR = s.Enabled
		case "shodan":
			opts.Shodan = s.Enabled
		case "bgphe":
			opts.BGPHE = s.Enabled
		case "ht":
			opts.HT = s.Enabled
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
		if n > maxThreads {
			n = maxThreads
		}
		threads = n
	}

	// ── Config summary ──
	srcList := []string{}
	if opts.PTR {
		srcList = append(srcList, "PTR")
	}
	if opts.Shodan {
		srcList = append(srcList, "Shodan")
	}
	if opts.BGPHE {
		srcList = append(srcList, "bgp.he.net")
	}
	if opts.HT {
		srcList = append(srcList, "hackertarget")
	}

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
