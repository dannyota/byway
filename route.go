package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	fwMark     = 0x100
	routeTable = 100
	rulePrio   = 32765
)

// Route manages the ip rule and routing table entry for fwmark-based policy routing.
type Route struct {
	mu       sync.Mutex
	iface    string
	gateway  net.IP
	link     netlink.Link
	shared   bool // true if iface carries the system default route (VPN's interface)
	logger   *slog.Logger
}

func NewRoute(iface string, logger *slog.Logger) *Route {
	return &Route{
		iface:  iface,
		logger: logger,
	}
}

// IsSharedInterface reports whether the configured interface is the same one
// carrying the system's default route (i.e. the VPN's interface). In shared
// mode the VPN may periodically flush our rules — the reconciler mitigates this.
// Must be called after DetectGateway.
func (r *Route) IsSharedInterface() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.shared
}

// DetectGateway finds the default gateway on the configured interface and
// determines whether the interface is shared with the system default route.
func (r *Route) DetectGateway() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.detectGatewayLocked()
}

func (r *Route) detectGatewayLocked() error {
	link, err := netlink.LinkByName(r.iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", r.iface, err)
	}
	r.link = link

	// Fetch all routes (not scoped to link) so we can both find the
	// interface's gateway and detect shared-interface mode in one pass.
	routes, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		return fmt.Errorf("listing routes: %w", err)
	}

	r.shared = false
	r.gateway = nil
	linkIdx := link.Attrs().Index

	for _, route := range routes {
		if route.Gw == nil || (!isDefaultRoute(route)) {
			continue
		}
		// First default route on any interface — check if it's ours.
		if !r.shared && route.LinkIndex == linkIdx {
			r.shared = true
		}
		// Default route on our interface — use as gateway.
		if r.gateway == nil && route.LinkIndex == linkIdx {
			r.gateway = route.Gw
		}
	}

	if r.gateway == nil {
		return fmt.Errorf("no default gateway found on %s", r.iface)
	}
	return nil
}

func isDefaultRoute(route netlink.Route) bool {
	return route.Dst == nil || route.Dst.IP.Equal(net.IPv4zero)
}

// Setup creates the ip rule (fwmark → table) and the route table entry (default via gateway).
func (r *Route) Setup() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.setupLocked()
}

func newBywayRule() *netlink.Rule {
	mask := uint32(0xFFFFFFFF)
	rule := netlink.NewRule()
	rule.Mark = fwMark
	rule.Mask = &mask
	rule.Table = routeTable
	rule.Priority = rulePrio
	rule.Family = unix.AF_INET
	return rule
}

func (r *Route) setupLocked() error {
	if err := netlink.RuleAdd(newBywayRule()); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("adding ip rule: %w", err)
		}
	}

	route := &netlink.Route{
		Gw:        r.gateway,
		Table:     routeTable,
		LinkIndex: r.link.Attrs().Index,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("adding route to table %d: %w", routeTable, err)
	}

	return nil
}

// Teardown removes the ip rule and route table entry.
func (r *Route) Teardown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.teardownLocked()
}

func (r *Route) teardownLocked() {
	if err := netlink.RuleDel(newBywayRule()); err != nil {
		if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENODATA) {
			r.logger.Warn("deleting ip rule", "err", err)
		}
	}

	if r.link != nil && r.gateway != nil {
		route := &netlink.Route{
			Gw:        r.gateway,
			Table:     routeTable,
			LinkIndex: r.link.Attrs().Index,
		}
		if err := netlink.RouteDel(route); err != nil {
			if !errors.Is(err, unix.ESRCH) {
				r.logger.Warn("deleting route", "err", err)
			}
		}
	}
}

// Verify checks that the ip rule and route still exist with correct values.
func (r *Route) Verify() (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check ip rule.
	rules, err := netlink.RuleList(unix.AF_INET)
	if err != nil {
		return false, fmt.Errorf("listing rules: %w", err)
	}

	ruleFound := false
	for _, rule := range rules {
		if rule.Mark == fwMark && rule.Table == routeTable {
			ruleFound = true
			break
		}
	}
	if !ruleFound {
		return false, nil
	}

	// Check route in table.
	filter := &netlink.Route{Table: routeTable}
	routes, err := netlink.RouteListFiltered(unix.AF_INET, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return false, fmt.Errorf("listing routes in table %d: %w", routeTable, err)
	}

	if len(routes) == 0 {
		return false, nil
	}

	// Verify the gateway is still correct.
	if r.link != nil {
		for _, route := range routes {
			if route.Gw != nil && route.Gw.Equal(r.gateway) && route.LinkIndex == r.link.Attrs().Index {
				return true, nil
			}
		}
		return false, nil
	}

	return true, nil
}

// Gateway returns the currently detected gateway IP.
func (r *Route) Gateway() net.IP {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.gateway
}

// UpdateInterface tears down existing rules/routes and sets up new ones for a different interface.
// Validates the new interface exists before tearing down the old one.
func (r *Route) UpdateInterface(iface string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Validate new interface before tearing down old routes.
	if _, err := netlink.LinkByName(iface); err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}

	r.teardownLocked()
	r.iface = iface
	if err := r.detectGatewayLocked(); err != nil {
		return err
	}
	return r.setupLocked()
}
