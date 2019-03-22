// Command makeqr will make a QR code on the terminal. It has built-in support for TOTP uri encoding.
// Released into the public domain or CC0 license.
package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"rsc.io/qr"
)

const block = "\u2588\u2588"

func main() {
	totpSecret := flag.String("totp", "", "Secret for Time-based One Time Password (use Issuer:your@account.com for content")
	lvl := flag.String("l", "L", "QR redundancy level (L,M,Q,H)")
	flag.Parse()

	checkBase32 := regexp.MustCompile("[^a-z234567=]")

	content := flag.Arg(0)
	if *totpSecret != "" {
		// is it already escaped?
		if strings.Contains(content, "%") {
			var err error
			content, err = url.QueryUnescape(content)
			if err != nil {
				content = flag.Arg(0)
			}
		}
		secret := checkBase32.ReplaceAllString(strings.ToLower(*totpSecret), "")
		parts := strings.SplitN(content, ":", 2)
		if len(parts) == 1 {
			// no issuer
			content = strings.Replace(url.QueryEscape(content), "+", "%20", -1)
			content = "otpauth://totp/" + content + "?secret=" + secret
		} else {
			issuer := strings.Replace(url.QueryEscape(parts[0]), "+", "%20", -1)
			account := strings.Replace(url.QueryEscape(parts[1]), "+", "%20", -1)
			content = "otpauth://totp/" + issuer + "%3A" + account + "?secret=" + secret + "&issuer=" + issuer
		}
	}

	qrLevel := qr.M
	switch *lvl {
	case "L", "l":
		qrLevel = qr.L
	case "H", "h":
		qrLevel = qr.H
	case "Q", "q":
		qrLevel = qr.Q
	}
	code, err := qr.Encode(content, qrLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to create QR code: ", err)
		os.Exit(1)
	}

	border := 4
	for b := 0; b < border; b++ {
		os.Stdout.WriteString(strings.Repeat(block, code.Size+2*border) + "\n")
	}
	for y := 0; y < code.Size; y++ {
		os.Stdout.WriteString(strings.Repeat(block, border))
		for x := 0; x < code.Size; x++ {
			if code.Black(x, y) {
				os.Stdout.WriteString("  ")
			} else {
				os.Stdout.WriteString(block)
			}
		}
		os.Stdout.WriteString(strings.Repeat(block, border) + "\n")
	}
	for b := 0; b < border; b++ {
		os.Stdout.WriteString(strings.Repeat(block, code.Size+2*border) + "\n")
	}
}
