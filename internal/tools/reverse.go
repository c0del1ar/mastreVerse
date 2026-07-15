package tools

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"mastreverse/internal/core"
	"os"
	"strconv"
	"strings"
	"time"
)

func RunReverseIPLookup() {
	core.Cls()
	core.Banner()

	// ── Connectivity check ──
	fmt.Printf("  %s[~]%s Checking connectivity...", core.Yellow+core.Bold, core.Rst)
	resp, err := core.Hc.Get(core.WhatsmyipURL)
	if err != nil {
		fmt.Printf("  %s[ERR] No internet. Check connection.%s\n\n", core.Red+core.Bold, core.Rst)
		os.Exit(1)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var myIP string
	json.Unmarshal(body, &myIP)
	fmt.Printf(" %s[OK]%s  outbound IP: %s%s%s\n\n", core.Green+core.Bold, core.Rst, core.Bold+core.Cyan, myIP, core.Rst)

	// ── core.Source selection (raw terminal mode) ──
	core.SelectSources()

	// ── Build opts ──
	opts := core.Options{}
	anyOn := false
	for _, s := range core.Srcs {
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
		case "rapiddns":
			opts.RapidDNS = s.Enabled
		case "gdoh":
			opts.GoogleDoH = s.Enabled
		case "cfdoh":
			opts.CloudflareDoH = s.Enabled
		}
	}
	if !anyOn {
		fmt.Printf("\n  %s[!] No sources selected.%s\n\n", core.Red, core.Rst)
		os.Exit(1)
	}

	// ── Switch to cooked mode ──
	if core.Rd == nil {
		core.Rd = bufio.NewReader(os.Stdin)
	}

	core.Cls()
	core.Banner()

	// ── File input ──
	fmt.Printf("  %sTARGET FILE%s\n", core.Bold+core.Cyan, core.Rst)
	core.Sep()
	fmt.Printf("  %sone IP or domain per line · lines starting with # are skipped%s\n\n", core.Dim, core.Rst)

	filePath := core.Ask("path", "e.g.  targets.txt   /home/user/ips.txt")
	if filePath == "" {
		fmt.Printf("\n  %s[!] No file provided.%s\n\n", core.Red, core.Rst)
		os.Exit(1)
	}
	targets := core.LoadTargets(filePath)
	if len(targets) == 0 {
		fmt.Printf("\n  %s[!] File is empty or not found.%s\n\n", core.Red, core.Rst)
		os.Exit(1)
	}
	fmt.Printf("\n  %s[+]%s %s%d%s targets loaded\n\n", core.Green+core.Bold, core.Rst, core.Bold+core.Yellow, len(targets), core.Rst)

	// ── Thread input ──
	fmt.Printf("  %sTHREADS%s\n", core.Bold+core.Cyan, core.Rst)
	core.Sep()
	fmt.Printf("  %smax %d · default 10%s\n\n", core.Dim, core.MaxThreads, core.Rst)

	threadStr := core.Ask("count", fmt.Sprintf("1-%d", core.MaxThreads))
	threads := 10
	if n, err := strconv.Atoi(threadStr); err == nil && n >= 1 {
		if n > core.MaxThreads {
			n = core.MaxThreads
		}
		threads = n
	}

	// ── Config summary ──
	srcList := []string{}
	for _, s := range core.Srcs {
		if s.Enabled {
			srcList = append(srcList, s.Name)
		}
	}

	core.Nl()
	fmt.Printf("  %sREADY%s\n", core.Bold+core.Cyan, core.Rst)
	core.Sep()
	fmt.Printf("  %-10s  %s%s%s\n", "sources", core.Green, strings.Join(srcList, "  "), core.Rst)
	fmt.Printf("  %-10s  %s%d%s entries\n", "targets", core.Bold+core.Yellow, len(targets), core.Rst)
	fmt.Printf("  %-10s  %s%d%s workers\n", "threads", core.Bold+core.Yellow, threads, core.Rst)
	fmt.Printf("  %-10s  %sResult/reversed.txt%s\n", "output", core.Cyan, core.Rst)
	core.Sep()
	core.Nl()

	// ── Confirm ──
	fmt.Printf("  %s[Y/n]%s  Start scan? ❯ ", core.Cyan+core.Bold, core.Rst)
	ans, _ := core.Rd.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))
	if ans == "n" || ans == "no" {
		fmt.Printf("\n  %sAborted.%s\n\n", core.Yellow, core.Rst)
		return
	}

	// ── Run ──
	core.Nl()
	fmt.Printf("  %sSCANNING%s  %s%d targets  //  %d threads%s\n", core.Bold+core.Green, core.Rst, core.Dim, len(targets), threads, core.Rst)
	core.Sep()
	core.Nl()

	t0 := time.Now()
	Run(targets, opts, threads)
	elapsed := time.Since(t0)

	// ── Done ──
	core.Nl()
	fmt.Printf("  %sDONE%s\n", core.Bold+core.Green, core.Rst)
	core.Sep()
	fmt.Printf("  %d targets  //  %.2fs elapsed\n", len(targets), elapsed.Seconds())
	fmt.Printf("  %sresults  ->  Result/reversed.txt%s\n", core.Cyan, core.Rst)
	core.Sep()
	core.Nl()
}
