package ipwhitelist

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/ip"
	"github.com/traefik/traefik/v2/pkg/tracing"
)

// myIPWhitelist es la estructura que implementa el middleware.
type myIPWhitelist struct {
	next           http.Handler
	whiteLister    *ip.WhiteLister
	xForwardedFor  bool
	proxy          bool
	xRealIPHeader  string
	name           string
	tracingHandler *tracing.HTTPHandlerWrapper
}

// New crea una nueva instancia del middleware myIPWhitelist.
func New(ctx context.Context, next http.Handler, config *dynamic.MyIPWhitelist, name string) (http.Handler, error) {
	whiteLister, err := ip.NewWhiteLister(config.SourceRange)
	if err != nil {
		return nil, err
	}

	return &myIPWhitelist{
		next:          next,
		whiteLister:   whiteLister,
		xForwardedFor: config.XForwardedFor,
		proxy:         config.Proxy,
		xRealIPHeader: config.XRealIPHeader,
		name:          name,
	}, nil
}

// ServeHTTP se encarga de interceptar las solicitudes y verificar si la dirección IP está en la lista blanca.
func (m *myIPWhitelist) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ipAddress := req.RemoteAddr
	if m.xForwardedFor {
		ipAddress = req.Header.Get("X-Forwarded-For")
	}

	if m.proxy && m.xRealIPHeader != "" {
		ipAddress = req.Header.Get(m.xRealIPHeader)
	}

	ipAddress = strings.Split(ipAddress, ":")[0]

	isAllowed := m.whiteLister.IsAllowed(net.ParseIP(ipAddress))
	if !isAllowed {
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	m.next.ServeHTTP(rw, req)
}
