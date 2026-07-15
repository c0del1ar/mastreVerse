package main

import (
	"fmt"
	"strings"
)

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
