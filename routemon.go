package main

import (
	"context"
	"log/slog"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// RouteMonitor watches for netlink route changes and triggers immediate
// reconciliation when byway's routing is affected. This eliminates the
// polling gap in shared-interface mode where the VPN may flush routes.
type RouteMonitor struct {
	linkIndex  int
	reconciler *Reconciler
	logger     *slog.Logger
}

func NewRouteMonitor(link netlink.Link, reconciler *Reconciler, logger *slog.Logger) *RouteMonitor {
	return &RouteMonitor{
		linkIndex:  link.Attrs().Index,
		reconciler: reconciler,
		logger:     logger,
	}
}

// Run subscribes to netlink route events and triggers reconciliation
// when relevant changes are detected. Blocks until ctx is cancelled.
func (m *RouteMonitor) Run(ctx context.Context) error {
	ch := make(chan netlink.RouteUpdate, 64)
	done := make(chan struct{})
	defer close(done)

	if err := netlink.RouteSubscribeWithOptions(ch, done, netlink.RouteSubscribeOptions{
		ErrorCallback: func(err error) {
			m.logger.Warn("route monitor error", "err", err)
		},
	}); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case update, ok := <-ch:
			if !ok {
				return nil
			}
			if m.isRelevant(update) {
				m.logger.Info("route change detected, triggering reconcile",
					"type", rtmName(update.Type),
					"table", update.Table,
				)
				m.reconciler.Trigger()
			}
		}
	}
}

// isRelevant returns true if the route change could affect byway's routing.
func (m *RouteMonitor) isRelevant(update netlink.RouteUpdate) bool {
	// Direct change to byway's routing table.
	if update.Table == routeTable {
		return true
	}

	// Default route change on our interface (VPN adding/removing its route).
	if update.LinkIndex == m.linkIndex && update.Dst == nil && update.Gw != nil {
		return true
	}

	return false
}

func rtmName(t uint16) string {
	switch t {
	case unix.RTM_NEWROUTE:
		return "add"
	case unix.RTM_DELROUTE:
		return "del"
	default:
		return "unknown"
	}
}
