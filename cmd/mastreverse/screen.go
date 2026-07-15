package main

import (
	"fmt"
	"strings"
)

const sepW = 51

func cls() { fmt.Print("\033[2J\033[H") }
func nl()  { fmt.Print("\r\n") }
func sep() { fmt.Printf("  %s%s%s\r\n", dim, strings.Repeat("-", sepW), rst) }

func banner() {
	fmt.Printf("%s%s\r\n", cyan+bold, "")
	fmt.Print("  ╔╦╗╔═╗╔═╗╔╦╗╦═╗╔═╗╦  ╦╔═╗╦═╗╔═╗╔═╗\r\n")
	fmt.Print("  ║║║╠═╣╚═╗ ║ ╠╦╝║╣ ╚╗╔╝║╣ ╠╦╝╚═╗║╣ \r\n")
	fmt.Print("  ╩ ╩╩ ╩╚═╝ ╩ ╩╚═╚═╝ ╚╝ ╚═╝╩╚═╚═╝╚═╝\r\n")
	fmt.Printf("%s", rst)
	fmt.Printf("\r  %sReverse IP Lookup & Blacklist Checker  %s[%s]%s\r\n", dim, cyan+bold, Version, dim+rst)
	sep()
	nl()
}
