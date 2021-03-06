package proxy

import (
	"fmt"
	"github.com/gobwas/glob"
	"github.com/jsiebens/brink/internal/config"
	"net"
	"strconv"
	"strings"
)

func parseTargetFilters(policies map[string]config.Policy) (map[string][]TargetFilter, error) {
	var filtersMap = map[string][]TargetFilter{}
	for name, policy := range policies {
		var filters []TargetFilter

		for _, f := range policy.Targets {
			filter, err := parseTargetFilter(f)
			if err != nil {
				return nil, err
			}
			filters = append(filters, filter)
		}
		filtersMap[name] = filters
	}
	return filtersMap, nil
}

func parseTargetFilter(rule string) (TargetFilter, error) {
	n := strings.Split(rule, ":")

	if len(n) != 2 {
		return nil, fmt.Errorf("invalid target rule [%s]", rule)
	}

	var portRanges []portRange

	if n[1] == "*" {
		portRanges = []portRange{{0, 65535}}
	} else {
		prs := strings.Split(n[1], ",")
		for _, pr := range prs {
			parsedPortRange, err := ParsePortRange(pr)
			if err != nil {
				return nil, err
			}
			portRanges = append(portRanges, *parsedPortRange)
		}
	}

	if n[0] == "*" {
		return &hostTargetFilter{n[0], nil, portRanges}, nil
	} else {
		var x = n[0]

		ip := net.ParseIP(n[0])
		if ip != nil {
			x = n[0] + "/32"
		}

		_, cidr, err := net.ParseCIDR(x)
		if err == nil {
			return &cidrTargetFilter{cidr, portRanges}, nil
		}

		compile, err := glob.Compile(n[0], '.')
		if err == nil {
			return &hostTargetFilter{n[0], compile, portRanges}, nil
		}

		return &hostTargetFilter{n[0], nil, portRanges}, nil
	}
}

func ParsePortRange(ranges string) (*portRange, error) {
	n := strings.SplitN(ranges, "-", 2)

	start, err := strconv.ParseUint(n[0], 10, 64)
	if err != nil {
		return nil, err
	}

	if len(n) == 1 {
		return &portRange{
			start: start,
			end:   start,
		}, nil
	}

	end, err := strconv.ParseUint(n[1], 10, 64)
	if err != nil {
		return nil, err
	}

	return &portRange{
		start: start,
		end:   end,
	}, nil
}

type TargetFilter interface {
	validate(host string, port uint64) bool
}

type cidrTargetFilter struct {
	cidr *net.IPNet
	port portRangeFilter
}

type hostTargetFilter struct {
	host    string
	pattern glob.Glob
	port    portRangeFilter
}

type portRange struct {
	start, end uint64
}

type portRangeFilter []portRange

func (p portRangeFilter) validate(port uint64) bool {
	for _, r := range p {
		if r.start <= port && port <= r.end {
			return true
		}
	}
	return false
}

func (r *hostTargetFilter) validate(target string, port uint64) bool {
	if !r.port.validate(port) {
		return false
	}

	if r.host == "*" || r.host == target {
		return true
	}

	if r.pattern != nil && r.pattern.Match(target) {
		return true
	}

	allowedIPs, err := net.LookupIP(r.host)
	if err != nil {
		return false
	}

	targetIP := net.ParseIP(target)
	if targetIP != nil {
		for _, ai := range allowedIPs {
			if ai.Equal(targetIP) {
				return true
			}
		}
	}

	targetIPs, err := net.LookupIP(target)
	if err != nil {
		return false
	}

	for _, ai := range allowedIPs {
		for _, ti := range targetIPs {
			if ai.Equal(ti) {
				return true
			}
		}
	}

	return false
}

func (r *cidrTargetFilter) validate(target string, port uint64) bool {
	if !r.port.validate(port) {
		return false
	}

	ip := net.ParseIP(target)
	if ip != nil {
		return r.cidr.Contains(ip)
	}

	ips, err := net.LookupIP(target)
	if err != nil {
		return false
	}

	for _, i := range ips {
		if r.cidr.Contains(i) {
			return true
		}
	}

	return false
}
