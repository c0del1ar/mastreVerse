package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type userResp struct {
	TempAuthKey string `json:"TempAuthKey"`
}

type lookupResp struct {
	HTMLValue string `json:"HTML_Value"`
}

func blacklistCheck(target string) {
	cls()
	banner()
	fmt.Printf("  %sBLACKLIST CHECKER%s\n", bold+cyan, rst)
	sep()
	fmt.Printf("  %sTarget:%s %s\n\n", dim, rst, target)
	fmt.Printf("  %s[~]%s Requesting token...\n", yellow+bold, rst)

	hc := &http.Client{Timeout: 15 * time.Second}

	// 1. Get TempAuthKey
	reqU, _ := http.NewRequest("GET", "https://mxtoolbox.com/api/v1/user", nil)
	reqU.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	reqU.Header.Set("Referer", "https://mxtoolbox.com/SuperTool.aspx")

	resU, err := hc.Do(reqU)
	if err != nil {
		fmt.Printf("  %s[!] Network error (auth):%s %v\n\n", red+bold, rst, err)
		fmt.Printf("  %sPress ENTER to return%s", dim, rst)
		rd.ReadString('\n')
		return
	}
	defer resU.Body.Close()

	var ur userResp
	json.NewDecoder(resU.Body).Decode(&ur)

	if ur.TempAuthKey == "" {
		fmt.Printf("  %s[!] Failed to get TempAuthKey.%s\n\n", red+bold, rst)
		fmt.Printf("  %sPress ENTER to return%s", dim, rst)
		rd.ReadString('\n')
		return
	}

	fmt.Printf("  %s[~]%s Checking against mxtoolbox...\n\n", yellow+bold, rst)

	// 2. Query Blacklist
	q := url.Values{}
	q.Set("command", "blacklist")
	q.Set("argument", target)
	q.Set("resultIndex", "1")
	q.Set("disableRhsbl", "true")
	q.Set("format", "2")

	req, _ := http.NewRequest("GET", "https://mxtoolbox.com/api/v1/Lookup?"+q.Encode(), nil)
	req.Header.Set("User-Agent", reqU.Header.Get("User-Agent"))
	req.Header.Set("Referer", reqU.Header.Get("Referer"))
	req.Header.Set("TempAuthorization", ur.TempAuthKey)

	res, err := hc.Do(req)
	if err != nil {
		fmt.Printf("  %s[!] Network error (lookup):%s %v\n", red+bold, rst, err)
	} else {
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)

		if res.StatusCode != 200 {
			fmt.Printf("  %s[!] API Error: HTTP %d%s\n", red+bold, res.StatusCode, rst)
		} else {
			var lr lookupResp
			json.Unmarshal(body, &lr)
			html := lr.HTMLValue
			if html == "" {
				html = string(body)
			}

			// Simple parsing for LISTED rows
			reRow := regexp.MustCompile(`(?s)<tr>.*?</tr>`)
			rows := reRow.FindAllString(html, -1)

			type BLResult struct {
				Name   string
				Reason string
			}
			var listed []BLResult

			for _, r := range rows {
				if strings.Contains(r, "bld_error") || strings.Contains(strings.ToUpper(r), "LISTED") || strings.Contains(r, "error-outline") || strings.Contains(r, "label-danger") {
					reTD := regexp.MustCompile(`(?s)<td[^>]*>(.*?)</td>`)
					tds := reTD.FindAllStringSubmatch(r, -1)
					if len(tds) >= 3 {
						reTags := regexp.MustCompile(`<[^>]*>`)
						name := strings.TrimSpace(reTags.ReplaceAllString(tds[1][1], ""))
						reason := strings.TrimSpace(reTags.ReplaceAllString(tds[2][1], ""))
						reason = strings.ReplaceAll(reason, "Detail", "")
						reason = strings.ReplaceAll(reason, "&nbsp;", " ")
						reason = strings.TrimSpace(reason)

						if name != "" && name != "Blacklist" {
							listed = append(listed, BLResult{Name: name, Reason: reason})
						}
					}
				}
			}

			if len(listed) > 0 {
				fmt.Printf("  %s[!] Listed in %d blacklists:%s\n", red+bold, len(listed), rst)
				for _, b := range listed {
					fmt.Printf("      - %s%-18s%s  %s%s%s\n", white+bold, b.Name, rst, dim, b.Reason, rst)
				}
			} else {
				fmt.Printf("  %s[OK] Not listed in any blacklists.%s\n", green+bold, rst)
			}
		}
	}

	fmt.Printf("\n  %sPress ENTER to return%s", dim, rst)
	rd.ReadString('\n')
}
