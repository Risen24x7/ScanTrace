// benign.go contains static CIDR ranges and IP lists for well-known research
// scanners and internet-measurement organisations that should never be treated
// as hostile, even when ip-api.com reports them as hosting infrastructure.
//
// Sources (all publicly documented):
//   - Shodan:           https://help.shodan.io/the-basics/what-are-the-shodan-crawlers
//   - Censys:           https://support.censys.io/hc/en-us/articles/360038761891
//   - Shadowserver:     https://www.shadowserver.org/what-we-do/network-reporting/our-scanner-ip-addresses/
//   - CAIDA:            https://www.caida.org/projects/ark/
//   - Univ. of Michigan / ZMap: https://zmap.io/
//
// NOTE: These ranges change occasionally.  Run `make feeds` to pull a fresh
// copy of the ipsum list; update this file manually when scanner prefixes change.
package threatfeed

import (
	"net"
)

// benignScannerCIDRs maps a human-readable scanner name to its known CIDR
// ranges. Kept as strings so they are easy to read / audit.
var benignScannerCIDRs = map[string][]string{
	"Shodan": {
		"66.240.192.0/19",
		"66.240.236.119/32",
		"66.240.239.0/24",
		"71.6.135.0/24",
		"71.6.146.0/24",
		"71.6.158.0/24",
		"71.6.165.0/24",
		"71.6.167.0/24",
		"85.208.96.0/24",
		"93.120.27.62/32",
		"104.131.0.69/32",
		"104.236.198.48/32",
		"185.142.236.0/24",
		"188.138.9.50/32",
		"209.126.110.0/24",
	},
	"Censys": {
		"162.142.125.0/24",
		"167.248.133.0/24",
		"167.248.132.0/24",
		"167.248.134.0/24",
		"216.238.85.0/24",
	},
	"Shadowserver": {
		"184.105.139.64/26",
		"184.105.143.128/26",
		"184.105.247.192/26",
		"74.82.47.0/26",
		"216.218.206.64/26",
	},
	"CAIDA Ark": {
		"192.172.226.0/24",
		"198.124.238.0/24",
	},
	"ZMap / UMich": {
		"141.212.0.0/16",
	},
}

// parsedBenignNets is the pre-compiled version of benignScannerCIDRs.
var parsedBenignNets []*parsedEntry

type parsedEntry struct {
	name string
	net  *net.IPNet
}

func init() {
	for name, cidrs := range benignScannerCIDRs {
		for _, cidr := range cidrs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			parsedBenignNets = append(parsedBenignNets, &parsedEntry{name: name, net: ipnet})
		}
	}
}

// IsBenignScanner returns (scannerName, true) if ip falls within a known
// research-scanner range, or ("", false) otherwise.
func IsBenignScanner(ipStr string) (string, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", false
	}
	for _, entry := range parsedBenignNets {
		if entry.net.Contains(ip) {
			return entry.name, true
		}
	}
	return "", false
}
