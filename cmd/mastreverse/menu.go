package main

import (
	"bufio"
	"fmt"
	"golang.org/x/term"
	"os"
	"regexp"
)

func selectTool() int {
	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		if rd == nil {
			rd = bufio.NewReader(os.Stdin)
		}
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
		if selected == 1 {
			p1 = ">"
			c1 = bold + green
		}
		if selected == 2 {
			p2 = ">"
			c2 = bold + green
		}

		fmt.Printf("\r  %s%s%s  Blacklist Checker\r\n", c1, p1, rst)
		fmt.Printf("\r  %s%s%s  Reverse IP Lookup\r\n", c2, p2, rst)

		nl()
		sep()
		fmt.Printf("\r  %sUP/DOWN%s move    %sENTER%s select\r\n", cyan+bold, rst, cyan+bold, rst)
		nl()
		fmt.Printf("\r  %s»%s ", green+bold, rst)

		n, _ := os.Stdin.Read(buf)
		if n == 0 {
			continue
		}

		if n == 3 && buf[0] == 27 && buf[1] == 91 { // escape sequence
			if buf[2] == 65 {
				selected = 1
			} // UP
			if buf[2] == 66 {
				selected = 2
			} // DOWN
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
