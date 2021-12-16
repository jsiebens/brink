package proxy

import (
	"net"
	"strconv"
	"strings"
)

type aclPolicy struct {
	identityFilters []string
	targetFilters   []*TargetFilter
}

func parseTargetFilters(filters []string) ([]*TargetFilter, error) {
	var result []*TargetFilter

	for _, f := range filters {
		filter, err := parseTargetFilter(f)
		if err != nil {
			return nil, err
		}
		result = append(result, filter)
	}

	return result, nil
}

func parseTargetFilter(rule string) (*TargetFilter, error) {
	n := strings.SplitN(rule, ":", 2)

	r := &TargetFilter{}

	if n[0] != "*" {
		var x = n[0]

		ip := net.ParseIP(n[0])
		if ip != nil {
			x = n[0] + "/32"
		}

		_, cidr, err := net.ParseCIDR(x)
		if err != nil {
			return nil, err
		}
		r.cidr = cidr
	}

	if n[1] != "*" {
		portRanges := strings.Split(n[1], ",")
		for _, pr := range portRanges {
			parsePortRange, err := ParsePortRange(pr)
			if err != nil {
				return nil, err
			}
			r.portRanges = append(r.portRanges, *parsePortRange)
		}
	}

	return r, nil
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

type TargetFilter struct {
	cidr       *net.IPNet
	portRanges []portRange
}

type portRange struct {
	start, end uint64
}

func (r *TargetFilter) validate(host string, port uint64) bool {
	if r.cidr != nil {
		ip := net.ParseIP(host)
		if ip == nil {
			ips, err := net.LookupIP(host)
			if err != nil {
				return false
			}

			for _, i := range ips {
				if !r.cidr.Contains(i) {
					return false
				}
			}
		} else {
			if !r.cidr.Contains(ip) {
				return false
			}
		}
	}

	if len(r.portRanges) != 0 {
		for _, p := range r.portRanges {
			if p.start <= port && port <= p.end {
				return true
			}
		}
		return false
	}

	// if cidr == nil && portrange empty -> allow all
	return true
}
