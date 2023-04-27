package main

import (
	"context"
	"net"
	"net/http"
)

type IPWhitelist struct {
	allowedIPs []net.IPNet
	next       http.Handler
}

type IPWhitelistConfig struct {
	AllowedIPs []string `json:"allowedIPs,omitempty"`
}

func New(ctx context.Context, next http.Handler, config *IPWhitelistConfig, name string) (http.Handler, error) {
	// Parse the list of allowed IPs from the configuration.
	allowedIPs := make([]net.IPNet, len(config.AllowedIPs))
	for i, cidr := range config.AllowedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		allowedIPs[i] = *ipNet
	}

	return &IPWhitelist{
		allowedIPs: allowedIPs,
		next:       next,
	}, nil
}

func (p *IPWhitelist) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Get the IP address of the request.
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Check if the IP address is allowed.
	allowed := false
	for _, ipNet := range p.allowedIPs {
		if ipNet.Contains(net.ParseIP(ip)) {
			allowed = true
			break
		}
	}

	// If the IP address is not allowed, return a 403 Forbidden status.
	if !allowed {
		http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// If the IP address is allowed, pass the request to the next handler.
	p.next.ServeHTTP(rw, req)
}
