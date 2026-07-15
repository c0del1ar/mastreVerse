package tools

import (
	"fmt"
	"mastreverse/internal/core"
	"os"
)

func RunBlacklistMenu() {
	core.Cls()
	core.Banner()
	fmt.Printf("  %sBLACKLIST CHECKER%s\n", core.Bold+core.Cyan, core.Rst)
	core.Sep()
	fmt.Printf("  %scheck IP or domain against 100+ blacklists%s\n\n", core.Dim, core.Rst)

	target := core.Ask("Target", "e.g. 8.8.8.8  or  example.com")
	if target == "" {
		fmt.Printf("\n  %s[!] No target provided.%s\n\n", core.Red, core.Rst)
		os.Exit(1)
	}

	BlacklistCheck(target)
}
