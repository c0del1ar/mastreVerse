package core

import (
	"fmt"
	"strings"
)

const sepW = 51

func Cls() { fmt.Print("\033[2J\033[H") }
func Nl()  { fmt.Print("\r\n") }
func Sep() { fmt.Printf("  %s%s%s\r\n", Dim, strings.Repeat("─", sepW), Rst) }

func Banner() {
	fmt.Printf("%s%s\r\n", Cyan+Bold, "")
	fmt.Print("  ╔╦╗╔═╗╔═╗╔╦╗╦═╗╔═╗╦  ╦╔═╗╦═╗╔═╗╔═╗\r\n")
	fmt.Print("  ║║║╠═╣╚═╗ ║ ╠╦╝║╣ ╚╗╔╝║╣ ╠╦╝╚═╗║╣ \r\n")
	fmt.Print("  ╩ ╩╩ ╩╚═╝ ╩ ╩╚═╚═╝ ╚╝ ╚═╝╩╚═╚═╝╚═╝\r\n")
	fmt.Printf("%s", Rst)
	fmt.Printf("\r  %sIP Lookup · Blacklist · Port Scanner  %s[%s]%s\r\n", Dim, Cyan+Bold, Version, Dim+Rst)
	Sep()
	Nl()
}
