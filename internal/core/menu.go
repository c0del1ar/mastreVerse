package core

import (
	"bufio"
	"fmt"
	"os"
	"regexp"

	"golang.org/x/term"
)

func SelectTool() int {
	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		if Rd == nil {
			Rd = bufio.NewReader(os.Stdin)
		}
		return 2 // Default to Reverse IP Lookup if not a TTY
	}
	defer term.Restore(fd, state)

	selected := 1
	buf := make([]byte, 4)
	for {
		Cls()
		Banner()

		fmt.Printf("\r  %sMAIN MENU%s\r\n", Bold+Cyan, Rst)
		Sep()
		Nl()

		p1, p2, p3 := "  ", "  ", "  "
		c1, c2, c3 := Dim+White, Dim+White, Dim+White
		if selected == 1 {
			p1 = "❯ "
			c1 = Bold + Cyan
		}
		if selected == 2 {
			p2 = "❯ "
			c2 = Bold + Cyan
		}
		if selected == 3 {
			p3 = "❯ "
			c3 = Bold + Cyan
		}

		fmt.Printf("\r    %s%sBlacklist Checker%s\r\n", c1, p1, Rst)
		fmt.Printf("\r    %s%sReverse IP Lookup%s\r\n", c2, p2, Rst)
		fmt.Printf("\r    %s%sOpen Port Finder%s\r\n", c3, p3, Rst)

		Nl()
		Sep()
		fmt.Printf("\r  %sUP/DOWN%s move    %sENTER%s select\r\n", Cyan+Bold, Rst, Cyan+Bold, Rst)
		Nl()
		fmt.Printf("\r  %s❯%s ", Cyan+Bold, Rst)

		n, _ := os.Stdin.Read(buf)
		if n == 0 {
			continue
		}

		if n == 3 && buf[0] == 27 && buf[1] == 91 { // escape sequence
			if buf[2] == 65 { // UP
				selected--
				if selected < 1 {
					selected = 3
				}
			}
			if buf[2] == 66 { // DOWN
				selected++
				if selected > 3 {
					selected = 1
				}
			}
		} else if buf[0] == 0x0d || buf[0] == '\n' {
			return selected
		} else if buf[0] == 0x03 {
			term.Restore(fd, state)
			fmt.Printf("\r\n  %sInterrupted.%s\r\n\r\n", Yellow, Rst)
			os.Exit(0)
		}
	}
}

// ══════════════════════════════════════════════════
//  CHECKBOX UI  (raw terminal)
// ══════════════════════════════════════════════════

func DrawSources() {
	Cls()
	Banner()

	// Header
	fmt.Printf("\r  %sSELECT SOURCES%s\r\n", Bold+Cyan, Rst)
	Sep()
	Nl()

	// Entries  — NO right border, no padding math needed
	// [ON ] / [OFF] always exactly 5 visible chars
	for i, s := range Srcs {
		var badge string
		if s.Enabled {
			badge = fmt.Sprintf("%s[%s◉%s]%s", Dim, Green, Dim, Rst)
		} else {
			badge = fmt.Sprintf("%s[%s◯%s]%s", Dim, Dim, Dim, Rst)
		}
		fmt.Printf("\r  %s%d%s  %s  %s%-18s%s  %s%s%s\r\n",
			Bold+Yellow, i+1, Rst,
			badge,
			White+Bold, s.Name, Rst,
			Dim, s.RateLabel, Rst)
	}

	Nl()
	Sep()
	fmt.Printf("\r  %s1-%d%s toggle    %sa%s all/none    %sENTER%s confirm\r\n",
		Cyan+Bold, len(Srcs), Rst, Cyan+Bold, Rst, Cyan+Bold, Rst)
	Nl()
	fmt.Printf("\r  %s❯%s ", Cyan+Bold, Rst)
}

func StripANSI(s string) string {
	re := regexp.MustCompile(`\033\[[0-9;]*m`)
	return re.ReplaceAllString(s, "")
}

func SelectSources() {
	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		// Not a real TTY — just initialize Rd and proceed with defaults (all sources on)
		Rd = bufio.NewReader(os.Stdin)
		return
	}
	defer term.Restore(fd, state)

	buf := make([]byte, 4)
	for {
		DrawSources()
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
			fmt.Printf("\n  %sInterrupted.%s\n\n", Yellow, Rst)
			os.Exit(0)
		case ch == 'a' || ch == 'A':
			allOn := true
			for _, s := range Srcs {
				if !s.Enabled {
					allOn = false
					break
				}
			}
			for i := range Srcs {
				Srcs[i].Enabled = !allOn
			}
		default:
			if ch >= '1' && int(ch-'1') < len(Srcs) {
				Srcs[ch-'1'].Enabled = !Srcs[ch-'1'].Enabled
			}
		}
	}
}
