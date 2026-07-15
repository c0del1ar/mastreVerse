package tools

import (
	"fmt"
	"mastreverse/internal/core"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func Run(targets []string, opts core.Options, threads int) {
	os.MkdirAll("Result", 0o755)
	outFile, ferr := os.Create("Result/reversed.txt")
	if ferr != nil {
		fmt.Printf("  %s[!] Cannot create output file: %v%s\n", core.Red, ferr, core.Rst)
	} else {
		defer outFile.Close()
	}

	total := int64(len(targets))
	var done int64

	// ── Printer goroutine (single writer to stdout) ──
	pch := make(chan core.Msg, 1024)
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
					core.Cyan+core.Bold, frames[fi%len(frames)], core.Rst, msg.Text)
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
				bar := core.Green + strings.Repeat("▓", pct) + core.Dim + strings.Repeat("░", 28-pct) + core.Rst
				pch <- core.Msg{"spin", fmt.Sprintf(
					"%s[%s%s]%s  %s%d/%d%s  scanning...",
					core.Bold+core.Cyan, bar, core.Bold+core.Cyan, core.Rst,
					core.Bold+core.Yellow, d, total, core.Rst,
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

			r := LookupAll(target, opts)
			n := int(atomic.AddInt64(&done, 1))

			pch <- core.Msg{"result", core.FmtResult(r, n, int(total))}

			if outFile != nil {
				fileMu.Lock()
				fmt.Fprint(outFile, core.FmtFile(r))
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
