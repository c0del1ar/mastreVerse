package tools

import (
	"encoding/json"
	"fmt"
	"io"
	"mastreverse/internal/core"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type userResp struct {
	TempAuthKey string `json:"TempAuthKey"`
}

type lookupResp struct {
	HTMLValue string `json:"HTML_Value"`
}

func BlacklistCheck(target string) {
	core.Cls()
	core.Banner()
	fmt.Printf("  %sBLACKLIST CHECKER%s\n", core.Bold+core.Cyan, core.Rst)
	core.Sep()
	fmt.Printf("  %sTarget:%s %s\n\n", core.Dim, core.Rst, target)
	fmt.Printf("  %s[~]%s Requesting token...\n", core.Yellow+core.Bold, core.Rst)

	// 1. Get TempAuthKey
	reqU, _ := http.NewRequest("GET", "https://mxtoolbox.com/api/v1/user", nil)
	reqU.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	reqU.Header.Set("Referer", "https://mxtoolbox.com/SuperTool.aspx")

	resU, err := core.Hc.Do(reqU)
	if err != nil {
		fmt.Printf("  %s[!] Network error (auth):%s %v\n\n", core.Red+core.Bold, core.Rst, err)
		fmt.Printf("  %sPress ENTER to return%s", core.Dim, core.Rst)
		core.Rd.ReadString('\n')
		return
	}
	defer resU.Body.Close()

	var ur userResp
	json.NewDecoder(resU.Body).Decode(&ur)

	if ur.TempAuthKey == "" {
		fmt.Printf("  %s[!] Failed to get TempAuthKey.%s\n\n", core.Red+core.Bold, core.Rst)
		fmt.Printf("  %sPress ENTER to return%s", core.Dim, core.Rst)
		core.Rd.ReadString('\n')
		return
	}

	fmt.Printf("  %s[~]%s Checking against mxtoolbox...\n\n", core.Yellow+core.Bold, core.Rst)

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

	res, err := core.Hc.Do(req)
	if err != nil {
		fmt.Printf("  %s[!] Network error (lookup):%s %v\n", core.Red+core.Bold, core.Rst, err)
	} else {
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)

		if res.StatusCode != 200 {
			fmt.Printf("  %s[!] API Error: HTTP %d%s\n", core.Red+core.Bold, res.StatusCode, core.Rst)
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
				fmt.Printf("  %s[!] Listed in %d blacklists:%s\n", core.Red+core.Bold, len(listed), core.Rst)
				for _, b := range listed {
					fmt.Printf("      - %s%-18s%s  %s%s%s\n", core.White+core.Bold, b.Name, core.Rst, core.Dim, b.Reason, core.Rst)
				}
			} else {
				fmt.Printf("  %s[OK] Not listed in any blacklists.%s\n", core.Green+core.Bold, core.Rst)
			}
		}
	}

	fmt.Printf("\n  %sPress ENTER to return%s", core.Dim, core.Rst)
	core.Rd.ReadString('\n')
}
