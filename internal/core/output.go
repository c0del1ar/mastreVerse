package core

import (
	"fmt"
	"strings"
)

const previewMax = 6

func FmtResult(r Result, n, total int) string {
	counter := fmt.Sprintf("%s[%s%03d/%03d%s]%s",
		Dim, Rst+Dim, n, total, Rst+Dim, Rst)

	if r.Err != nil {
		return fmt.Sprintf(
			"  %s╭─%s %s %s✗%s  %s%s%s\n  %s╰─➤%s %s[FAIL] %v%s\n",
			Dim, Rst, counter, Red+Bold, Rst,
			Bold+Yellow, r.Target, Rst,
			Dim, Rst, Red, r.Err, Rst)
	}

	// Target label
	targetLabel := fmt.Sprintf("%s%s%s", Bold+Yellow, r.IP, Rst)
	if r.Target != r.IP {
		targetLabel = fmt.Sprintf("%s%s%s %s→%s %s%s%s",
			Bold+Yellow, r.Target, Rst,
			Dim, Rst,
			Bold+Cyan, r.IP, Rst)
	}

	// Domain list preview
	count := len(r.Domains)
	var domStr string
	if count == 0 {
		domStr = Dim + "(no results)" + Rst
	} else {
		preview := r.Domains
		more := 0
		if count > previewMax {
			preview = r.Domains[:previewMax]
			more = count - previewMax
		}
		parts := make([]string, len(preview))
		for i, d := range preview {
			parts[i] = White + d + Rst
		}
		domStr = strings.Join(parts, Dim+", "+Rst)
		if more > 0 {
			domStr += fmt.Sprintf(" %s... +%d more%s", Dim+Yellow, more, Rst)
		}
	}

	timing := fmt.Sprintf("%s%.1fs%s", Dim, r.Elapsed.Seconds(), Rst)

	return fmt.Sprintf(
		"  %s╭─%s %s %s✓%s  %s %s\n  %s╰─➤%s %s[%s]%s\n",
		Dim, Rst, counter,
		Green+Bold, Rst,
		targetLabel, timing,
		Dim, Rst,
		Bold+Green, domStr, Rst)
}

func FmtFile(r Result) string {
	if r.Err != nil || len(r.Domains) == 0 {
		return ""
	}
	return strings.Join(r.Domains, "\n") + "\n"
}
