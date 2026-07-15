package core

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func Ask(label, hint string) string {
	fmt.Printf("  %s%s%s  %s%s%s\n  %s❯%s ",
		Bold+Cyan, label, Rst,
		Dim, hint, Rst,
		Cyan+Bold, Rst)
	line, _ := Rd.ReadString('\n')
	return strings.TrimFunc(line, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
}

func LoadTargets(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		fmt.Printf("  %s[!] Cannot open file: %v%s\n", Red+Bold, err, Rst)
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
