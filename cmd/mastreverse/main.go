package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
)

var Version = "v1.0.0"

func main() {
	var showVer bool
	flag.BoolVar(&showVer, "v", false, "show version")
	flag.BoolVar(&showVer, "version", false, "show version")
	flag.Parse()

	if showVer {
		fmt.Printf("mastreVerse %s\n", Version)
		return
	}

	tool := selectTool()

	if rd == nil {
		rd = bufio.NewReader(os.Stdin)
	}

	if tool == 1 {
		runBlacklistMenu()
		return
	}

	runReverseIPLookup()
}
