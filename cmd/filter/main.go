// Command filter produces filtered copies of the SagerNet
// sing-geosite / sing-geoip CN rule sets.
//
// The upstream CN data claims Google: geosite-cn carries
// Google host entries (dl.google.com, googleapis, gvt,
// gstatic), and any Google range that ever lands in
// geoip-cn would go with it. Traffic matched by a CN rule
// set is usually sent direct, which breaks Google services
// such as Play Store downloads. This tool strips every
// Google entry from both sets:
//
//   - geosite-cn: drop domain / domain_suffix /
//     domain_keyword / domain_regex entries mentioning a
//     Google host token.
//   - geoip-cn: subtract Google's published IP ranges
//     (https://www.gstatic.com/ipranges/goog.json and
//     https://www.gstatic.com/ipranges/cloud.json) from
//     every ip_cidr entry.
//
// Usage:
//
//	filter geosite <in.srs> <out.srs>
//	filter geoip <in.srs> <out.srs> <ranges.json>...
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
)

var googleHostTokens = []string{
	"google", "gstatic", "gvt", "ggpht", "youtube", "doubleclick",
}

func isGoogleHostEntry(value string) bool {
	lower := strings.ToLower(value)
	for _, token := range googleHostTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func filterHostEntries(values []string) []string {
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if !isGoogleHostEntry(value) {
			kept = append(kept, value)
		}
	}
	return kept
}

func readRuleSet(path string) (option.PlainRuleSetCompat, option.PlainRuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return option.PlainRuleSetCompat{}, option.PlainRuleSet{}, err
	}
	compat, err := srs.Read(bytes.NewReader(data), true)
	if err != nil {
		return option.PlainRuleSetCompat{}, option.PlainRuleSet{}, err
	}
	plain, err := compat.Upgrade()
	if err != nil {
		return option.PlainRuleSetCompat{}, option.PlainRuleSet{}, err
	}
	return compat, plain, nil
}

func writeRuleSet(path string, compat option.PlainRuleSetCompat, plain option.PlainRuleSet) error {
	var buffer bytes.Buffer
	if err := srs.Write(&buffer, plain, compat.Version); err != nil {
		return err
	}
	return os.WriteFile(path, buffer.Bytes(), 0o644)
}

func filterGeosite(inPath, outPath string) error {
	compat, plain, err := readRuleSet(inPath)
	if err != nil {
		return err
	}
	removed := 0
	rules := make([]option.HeadlessRule, 0, len(plain.Rules))
	for _, rule := range plain.Rules {
		if rule.Type == "" || rule.Type == "default" {
			before := len(rule.DefaultOptions.Domain) + len(rule.DefaultOptions.DomainSuffix) +
				len(rule.DefaultOptions.DomainKeyword) + len(rule.DefaultOptions.DomainRegex)
			rule.DefaultOptions.Domain = filterHostEntries(rule.DefaultOptions.Domain)
			rule.DefaultOptions.DomainSuffix = filterHostEntries(rule.DefaultOptions.DomainSuffix)
			rule.DefaultOptions.DomainKeyword = filterHostEntries(rule.DefaultOptions.DomainKeyword)
			rule.DefaultOptions.DomainRegex = filterHostEntries(rule.DefaultOptions.DomainRegex)
			after := len(rule.DefaultOptions.Domain) + len(rule.DefaultOptions.DomainSuffix) +
				len(rule.DefaultOptions.DomainKeyword) + len(rule.DefaultOptions.DomainRegex)
			removed += before - after
			if after == 0 && len(rule.DefaultOptions.IPCIDR) == 0 && len(rule.DefaultOptions.SourceIPCIDR) == 0 {
				continue
			}
		}
		rules = append(rules, rule)
	}
	plain.Rules = rules
	if err := writeRuleSet(outPath, compat, plain); err != nil {
		return err
	}
	fmt.Printf("geosite: removed %d Google host entries\n", removed)
	return nil
}

type googRanges struct {
	Prefixes []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
		IPv6Prefix string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

func loadGooglePrefixes(paths []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var doc googRanges
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, err
		}
		for _, entry := range doc.Prefixes {
			text := entry.IPv4Prefix
			if text == "" {
				text = entry.IPv6Prefix
			}
			if text == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	return prefixes, nil
}

// subtractPrefix returns base with cut removed, splitting
// base as needed. Both must be masked and of one family.
func subtractPrefix(base, cut netip.Prefix) []netip.Prefix {
	if base.Addr().BitLen() != cut.Addr().BitLen() {
		return []netip.Prefix{base}
	}
	if !base.Overlaps(cut) {
		return []netip.Prefix{base}
	}
	if cut.Contains(base.Addr()) && cut.Bits() <= base.Bits() {
		return nil
	}
	// Split base into its two halves and recurse.
	bits := base.Bits()
	halfBits := bits + 1
	addr := base.Addr()
	lower := netip.PrefixFrom(addr, halfBits).Masked()
	upperAddr := addr
	// Set the bit that distinguishes the upper half.
	if addr.Is4() {
		b := addr.As4()
		byteIdx := bits / 8
		bitIdx := 7 - (bits % 8)
		b[byteIdx] |= 1 << bitIdx
		upperAddr = netip.AddrFrom4(b)
	} else {
		b := addr.As16()
		byteIdx := bits / 8
		bitIdx := 7 - (bits % 8)
		b[byteIdx] |= 1 << bitIdx
		upperAddr = netip.AddrFrom16(b)
	}
	upper := netip.PrefixFrom(upperAddr, halfBits).Masked()
	out := subtractPrefix(lower, cut)
	out = append(out, subtractPrefix(upper, cut)...)
	return out
}

func parseCIDR(text string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func filterGeoIP(inPath, outPath string, rangePaths []string) error {
	google, err := loadGooglePrefixes(rangePaths)
	if err != nil {
		return err
	}
	compat, plain, err := readRuleSet(inPath)
	if err != nil {
		return err
	}
	removedEntries := 0
	keptEntries := 0
	rules := make([]option.HeadlessRule, 0, len(plain.Rules))
	for _, rule := range plain.Rules {
		if (rule.Type == "" || rule.Type == "default") && len(rule.DefaultOptions.IPCIDR) > 0 {
			out := make([]string, 0, len(rule.DefaultOptions.IPCIDR))
			for _, text := range rule.DefaultOptions.IPCIDR {
				prefix, err := parseCIDR(text)
				if err != nil {
					out = append(out, text)
					continue
				}
				remaining := []netip.Prefix{prefix}
				for _, cut := range google {
					next := make([]netip.Prefix, 0, len(remaining))
					for _, piece := range remaining {
						next = append(next, subtractPrefix(piece, cut)...)
					}
					remaining = next
					if len(remaining) == 0 {
						break
					}
				}
				if len(remaining) == 0 {
					removedEntries++
					continue
				}
				for _, piece := range remaining {
					out = append(out, piece.String())
					keptEntries++
				}
			}
			rule.DefaultOptions.IPCIDR = out
			if len(out) == 0 && len(rule.DefaultOptions.Domain) == 0 &&
				len(rule.DefaultOptions.DomainSuffix) == 0 &&
				len(rule.DefaultOptions.DomainKeyword) == 0 &&
				len(rule.DefaultOptions.DomainRegex) == 0 {
				continue
			}
		}
		rules = append(rules, rule)
	}
	plain.Rules = rules
	if err := writeRuleSet(outPath, compat, plain); err != nil {
		return err
	}
	fmt.Printf("geoip: removed %d Google-covered entries, kept %d\n", removedEntries, keptEntries)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: filter geosite <in> <out> | filter geoip <in> <goog.json> <out>")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "geosite":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: filter geosite <in.srs> <out.srs>")
			os.Exit(2)
		}
		err = filterGeosite(os.Args[2], os.Args[3])
	case "geoip":
		if len(os.Args) < 5 {
			fmt.Fprintln(os.Stderr, "usage: filter geoip <in.srs> <out.srs> <ranges.json>...")
			os.Exit(2)
		}
		err = filterGeoIP(os.Args[2], os.Args[3], os.Args[4:])
	default:
		fmt.Fprintln(os.Stderr, "unknown mode:", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "filter failed:", err)
		os.Exit(1)
	}
}
