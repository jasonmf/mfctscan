package main

import (
	"net"
	"strings"
	"sync"
)

// A Resolver handles concurrent DNS resolution on Records.
type Resolver struct {
	in       chan Record
	out      chan Record
	lock     *sync.Mutex
	resolved map[string]struct{}
}

// Resolve loops over a stream of Record structs, performing DNS resolution and
// streaming out results.
func (r Resolver) Resolve() error {
	for record := range r.in {
		r.lock.Lock()
		if _, present := r.resolved[record.Name]; present {
			r.lock.Unlock()
			// This domain has already been resolved
			continue
		}
		r.resolved[record.Name] = struct{}{}
		r.lock.Unlock()

		if strings.HasPrefix(record.Name, "*") || strings.HasPrefix(record.Name, `"`) {
			// wildcard records won't resolve. Non-DNS Subjects won't resolve
			r.out <- record
			continue
		}

		record.Addrs, record.Err = net.LookupHost(record.Name)
		r.out <- record
	}
	return nil
}
