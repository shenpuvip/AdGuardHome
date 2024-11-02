package dnsforward

import (
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"net"
)

func ecsFromMsg(m *dns.Msg) (subnet *net.IPNet, scope int) {
	opt := m.IsEdns0()
	if opt == nil {
		return nil, 0
	}

	var ip net.IP
	var mask net.IPMask
	for _, e := range opt.Option {
		sn, ok := e.(*dns.EDNS0_SUBNET)
		if !ok {
			continue
		}

		switch sn.Family {
		case 1:
			ip = sn.Address.To4()
			mask = net.CIDRMask(int(sn.SourceNetmask), netutil.IPv4BitLen)
		case 2:
			ip = sn.Address
			mask = net.CIDRMask(int(sn.SourceNetmask), netutil.IPv6BitLen)
		default:
			continue
		}

		return &net.IPNet{IP: ip, Mask: mask}, int(sn.SourceScope)
	}

	return nil, 0
}

func popEdns0(m *dns.Msg) {
	// RFC 6891, Section 6.1.1 allows the OPT record to appear
	// anywhere in the additional record section, but it's usually at
	// the end so start there.
	for i := len(m.Extra) - 1; i >= 0; i-- {
		if m.Extra[i].Header().Rrtype == dns.TypeOPT {
			m.Extra = append(m.Extra[:i], m.Extra[i+1:]...)
		}
	}
}
