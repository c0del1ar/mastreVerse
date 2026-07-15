package main

import (
	"bufio"
	"flag"
	"fmt"
	"mastreverse/internal/core"
	"mastreverse/internal/tools"
	"os"
)

func main() {
	var showVer bool
	flag.BoolVar(&showVer, "v", false, "show version")
	flag.BoolVar(&showVer, "version", false, "show version")
	flag.Parse()

	if showVer {
		fmt.Printf("mastreVerse %s\n", core.Version)
		return
	}

	tool := core.SelectTool()

	if core.Rd == nil {
		core.Rd = bufio.NewReader(os.Stdin)
	}

	if tool == 1 {
		tools.RunBlacklistMenu()
		return
	}

	if tool == 3 {
		tools.RunOpenPortMenu()
		return
	}

	tools.RunReverseIPLookup()
}
