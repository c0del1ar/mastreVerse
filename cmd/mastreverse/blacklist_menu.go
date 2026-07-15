package main

import (
	"fmt"
	"os"
)

func runBlacklistMenu() {
	cls()
	banner()
	fmt.Printf("  %sBLACKLIST CHECKER%s\n", bold+cyan, rst)
	sep()
	fmt.Printf("  %scheck IP or domain against 100+ blacklists%s\n\n", dim, rst)

	target := ask("Target", "e.g. 8.8.8.8  or  example.com")
	if target == "" {
		fmt.Printf("\n  %s[!] No target provided.%s\n\n", red, rst)
		os.Exit(1)
	}

	blacklistCheck(target)
}
