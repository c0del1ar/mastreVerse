package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

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
