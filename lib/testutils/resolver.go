/*
 *
 * k6 - a next-generation load testing tool
 * Copyright (C) 2020 Load Impact
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package testutils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"golang.org/x/net/dns/dnsmessage"
)

// MockResolver implements netext.DNSResolver, and allows changing the host
// mapping at runtime.
type MockResolver struct {
	m     sync.RWMutex
	hosts map[string]net.IP
}

func NewMockResolver(hosts map[string]net.IP) *MockResolver {
	if hosts == nil {
		hosts = make(map[string]net.IP)
	}
	return &MockResolver{hosts: hosts}
}

func (r *MockResolver) Fetch(host string) (net.IP, error) {
	r.m.RLock()
	defer r.m.RUnlock()
	if ip, ok := r.hosts[host]; ok {
		return ip, nil
	}
	return nil, fmt.Errorf("lookup %s: no such host", host)
}

func (mr *MockResolver) handle(s net.Conn) {
	for {
		b := make([]byte, 512)
		n, err := s.Read(b)
		if err != nil {
			return
		}

		var msg dnsmessage.Message
		// FIXME: This returns the error `unpacking Question.Name: segment prefix is reserved`
		// https://github.com/golang/net/blob/62affa334b73ec65ed44a326519ac12c421905e3/dns/dnsmessage/message.go#L1999
		if err := msg.Unpack(b[:n]); err != nil {
			spew.Dump(err)
			return
		}

		if len(msg.Questions) == 0 {
			return
		}
		q := msg.Questions[0]
		if q.Type != dnsmessage.TypeA {
			return
		}

		ip, err := mr.Fetch(q.Name.String())
		if err != nil {
			// TODO: Write NXDOMAIN response?
			return
		}

		var ip4 [4]byte
		copy(ip4[:], ip)

		msg.Header.Response = true
		msg.Answers = []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   q.Type,
					Class:  q.Class,
					Length: 4,
				},
				Body: &dnsmessage.AResource{
					A: ip4,
				},
			},
		}

		b, err = msg.Pack()
		if err != nil {
			return
		}
		s.Write(b)
	}
}

func (r *MockResolver) Set(host, ip string) {
	r.m.Lock()
	defer r.m.Unlock()
	r.hosts[host] = net.ParseIP(ip)
}

type BaseMockResolver struct {
	*net.Resolver
	mr *MockResolver
}

func NewMockDNSServer(mr *MockResolver) *net.Resolver {
	c, s := net.Pipe()

	go mr.handle(s)

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return c, nil
		},
	}
}

// This is another mocking approach copied from go/src/net/dnsclient_unix_test.go that additionally
// mocks net.Conn, but the net.Pipe() approach is much simpler so I'd prefer to get that working.
type fakeDNSServer struct {
	rh        func(n, s string, q dnsmessage.Message, t time.Time) (dnsmessage.Message, error)
	alwaysTCP bool
}

func (server *fakeDNSServer) DialContext(_ context.Context, n, s string) (net.Conn, error) {
	if server.alwaysTCP || n == "tcp" || n == "tcp4" || n == "tcp6" {
		return &fakeDNSConn{tcp: true, server: server, n: n, s: s}, nil
	}
	return &fakeDNSPacketConn{fakeDNSConn: fakeDNSConn{tcp: false, server: server, n: n, s: s}}, nil
}

type fakeDNSConn struct {
	net.Conn
	tcp    bool
	server *fakeDNSServer
	n      string
	s      string
	q      dnsmessage.Message
	t      time.Time
	buf    []byte
}

func (f *fakeDNSConn) Close() error {
	return nil
}

func (f *fakeDNSConn) Read(b []byte) (int, error) {
	if len(f.buf) > 0 {
		n := copy(b, f.buf)
		f.buf = f.buf[n:]
		return n, nil
	}

	resp, err := f.server.rh(f.n, f.s, f.q, f.t)
	if err != nil {
		return 0, err
	}

	bb := make([]byte, 2, 514)
	bb, err = resp.AppendPack(bb)
	if err != nil {
		return 0, fmt.Errorf("cannot marshal DNS message: %v", err)
	}

	if f.tcp {
		l := len(bb) - 2
		bb[0] = byte(l >> 8)
		bb[1] = byte(l)
		f.buf = bb
		return f.Read(b)
	}

	bb = bb[2:]
	if len(b) < len(bb) {
		return 0, errors.New("read would fragment DNS message")
	}

	copy(b, bb)
	return len(bb), nil
}

func (f *fakeDNSConn) Write(b []byte) (int, error) {
	if f.tcp && len(b) >= 2 {
		b = b[2:]
	}
	if f.q.Unpack(b) != nil {
		return 0, fmt.Errorf("cannot unmarshal DNS message fake %s (%d)", f.n, len(b))
	}
	return len(b), nil
}

func (f *fakeDNSConn) SetDeadline(t time.Time) error {
	f.t = t
	return nil
}

type fakeDNSPacketConn struct {
	net.PacketConn
	fakeDNSConn
}

func (f *fakeDNSPacketConn) SetDeadline(t time.Time) error {
	return f.fakeDNSConn.SetDeadline(t)
}

func (f *fakeDNSPacketConn) Close() error {
	return f.fakeDNSConn.Close()
}
