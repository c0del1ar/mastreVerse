package tools

import (
	"encoding/json"
	"fmt"
	"mastreverse/internal/core"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type PortResult struct {
	IP    string `json:"ip"`
	Ports []int  `json:"port"`
}

func RunOpenPortMenu() {
	core.Cls()
	core.Banner()
	fmt.Printf("  %sOPEN PORT FINDER%s\n", core.Bold+core.Cyan, core.Rst)
	core.Sep()
	fmt.Printf("  %sfind common open ports on target IPs/domains%s\n\n", core.Dim, core.Rst)

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

	threadStr := core.Ask("count", fmt.Sprintf("1-%d", core.MaxThreads))
	threads := 10
	if n, err := strconv.Atoi(threadStr); err == nil && n >= 1 {
		if n > core.MaxThreads {
			n = core.MaxThreads
		}
		threads = n
	}

	core.Nl()
	fmt.Printf("  %sREADY%s\n", core.Bold+core.Cyan, core.Rst)
	core.Sep()
	fmt.Printf("  %-10s  %s%d%s entries\n", "targets", core.Bold+core.Yellow, len(targets), core.Rst)
	fmt.Printf("  %-10s  %s%d%s workers\n", "threads", core.Bold+core.Yellow, threads, core.Rst)
	fmt.Printf("  %-10s  %sResult/openports/%s\n", "output", core.Cyan, core.Rst)
	core.Sep()
	core.Nl()

	fmt.Printf("  %s[Y/n]%s  Start scan? ❯ ", core.Cyan+core.Bold, core.Rst)
	ans, _ := core.Rd.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))
	if ans == "n" || ans == "no" {
		fmt.Printf("\n  %sAborted.%s\n\n", core.Yellow, core.Rst)
		return
	}

	core.Nl()
	fmt.Printf("  %sSCANNING%s  %s%d targets  //  %d threads%s\n", core.Bold+core.Green, core.Rst, core.Dim, len(targets), threads, core.Rst)
	core.Sep()
	core.Nl()

	t0 := time.Now()
	RunPortScan(targets, threads)
	elapsed := time.Since(t0)

	core.Nl()
	fmt.Printf("  %sDONE%s\n", core.Bold+core.Green, core.Rst)
	core.Sep()
	fmt.Printf("  %d targets  //  %.2fs elapsed\n", len(targets), elapsed.Seconds())
	fmt.Printf("  %sresults  ->  Result/openports/%s\n", core.Cyan, core.Rst)
	core.Sep()
	core.Nl()
}

func RunPortScan(targets []string, threads int) {
	os.MkdirAll("Result/openports", 0755)
	outFile, _ := os.Create("Result/openports/openports.jsonl")
	if outFile != nil {
		defer outFile.Close()
	}
	liveFile, _ := os.Create("Result/openports/live.txt")
	if liveFile != nil {
		defer liveFile.Close()
	}

	total := int64(len(targets))
	var done int64
	pch := make(chan core.Msg, 100)
	var prWg sync.WaitGroup

	// UI drawing routine
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
				fmt.Printf("\r\033[K  %s%s%s %s", core.Cyan+core.Bold, frames[fi%len(frames)], core.Rst, msg.Text)
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
				bar := core.Green + strings.Repeat("▓", pct) + core.Dim + strings.Repeat("░", 28-pct) + core.Rst
				pch <- core.Msg{"spin", fmt.Sprintf(
					"%s[%s%s]%s  %s%d/%d%s  scanning ports...",
					core.Bold+core.Cyan, bar, core.Bold+core.Cyan, core.Rst,
					core.Bold+core.Yellow, d, total, core.Rst,
				)}
			case <-spinStop:
				return
			}
		}
	}()

	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	var fileMu sync.Mutex

	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 194, 443, 445, 1433, 3306, 3389, 5632, 5900, 25565}

	for _, target := range targets {
		target := target
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			// Resolve IP
			ipStr := target
			if net.ParseIP(target) == nil {
				addrs, err := net.LookupHost(target)
				if err == nil && len(addrs) > 0 {
					ipStr = addrs[0]
				}
			}

			// Scan Ports concurrently for this target
			var openPorts []int
			var pwg sync.WaitGroup
			var pmu sync.Mutex

			for _, p := range commonPorts {
				pwg.Add(1)
				go func(port int) {
					defer pwg.Done()
					addr := net.JoinHostPort(ipStr, strconv.Itoa(port))
					conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
					if err == nil {
						conn.Close()
						pmu.Lock()
						openPorts = append(openPorts, port)
						pmu.Unlock()
					}
				}(p)
			}
			pwg.Wait()

			n := int(atomic.AddInt64(&done, 1))

			// Format for stdout
			portsStr := []string{}
			for _, p := range openPorts {
				portsStr = append(portsStr, strconv.Itoa(p))
			}

			status := core.Green + "✓" + core.Rst
			if len(openPorts) == 0 {
				status = core.Red + "✗" + core.Rst
			}

			displayStr := fmt.Sprintf("  %s╭─%s[%s%03d/%03d%s] %s %s%s%s\n  %s╰─➤%s [%s]\n",
				core.Dim, core.Rst,
				core.Rst+core.Dim, n, total, core.Rst+core.Dim,
				status,
				core.Bold+core.Yellow, target, core.Rst,
				core.Dim, core.Rst,
				strings.Join(portsStr, ", "))

			pch <- core.Msg{"result", displayStr}

			// Save to file
			if outFile != nil {
				res := PortResult{IP: ipStr, Ports: openPorts}
				if res.Ports == nil {
					res.Ports = []int{}
				}
				b, _ := json.Marshal(res)

				fileMu.Lock()
				fmt.Fprintf(outFile, "%s\n", string(b))
				if len(openPorts) > 0 && liveFile != nil {
					fmt.Fprintf(liveFile, "%s\n", target)
				}
				fileMu.Unlock()
			}
		}()
	}

	wg.Wait()
	close(spinStop)
	pch <- core.Msg{"clear", ""}
	close(pch)
	prWg.Wait()
}
