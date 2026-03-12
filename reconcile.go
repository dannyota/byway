package main

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// Reconciler periodically verifies and restores byway infrastructure.
type Reconciler struct {
	nft        *NFT
	route      *Route
	procmon    *ProcMon
	cgroupID   uint64
	fwmark     uint32
	intervalCh chan time.Duration
	logger     *slog.Logger
}

func NewReconciler(nft *NFT, route *Route, procmon *ProcMon, cgroupID uint64, fwmark uint32, logger *slog.Logger) *Reconciler {
	return &Reconciler{
		nft:        nft,
		route:      route,
		procmon:    procmon,
		cgroupID:   cgroupID,
		fwmark:     fwmark,
		intervalCh: make(chan time.Duration, 1),
		logger:     logger,
	}
}

// UpdateInterval changes the reconciliation interval dynamically.
func (r *Reconciler) UpdateInterval(d time.Duration) {
	select {
	case r.intervalCh <- d:
	default:
	}
}

// Run executes the reconcile loop at the given interval until ctx is cancelled.
func (r *Reconciler) Run(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case newInterval := <-r.intervalCh:
			ticker.Reset(newInterval)
			r.logger.Info("reconcile interval updated", "interval", newInterval)
		case <-ticker.C:
			r.reconcileOnce()
		}
	}
}

func (r *Reconciler) reconcileOnce() {
	// Check cgroup.
	if _, err := os.Stat(cgroupPath); os.IsNotExist(err) {
		r.logger.Info("restoring cgroup")
		newID, err := CreateCgroup()
		if err != nil {
			r.logger.Error("restoring cgroup", "err", err)
			return
		}
		if newID != r.cgroupID {
			r.cgroupID = newID
			r.logger.Info("cgroup ID changed, updating nftables", "newID", newID)
			// Setup internally deletes the old table before creating the new one,
			// so there's no separate Teardown call that could leave us with no rules.
			if err := r.nft.Setup(newID, r.fwmark); err != nil {
				r.logger.Error("restoring nftables after cgroup recreate", "err", err)
				return
			}
		}
		// Cgroup was recreated — re-scan processes to move them back in.
		if err := r.procmon.ScanExisting(); err != nil {
			r.logger.Warn("re-scanning processes after cgroup restore", "err", err)
		}
		return
	}

	// Check nftables.
	nftOK, err := r.nft.Verify()
	if err != nil {
		r.logger.Warn("nftables verify failed", "err", err)
	}
	if !nftOK {
		r.logger.Info("restoring nftables rules")
		if err := r.nft.Setup(r.cgroupID, r.fwmark); err != nil {
			r.logger.Error("restoring nftables", "err", err)
		}
	}

	// Check routing.
	routeOK, err := r.route.Verify()
	if err != nil {
		r.logger.Warn("route verify failed", "err", err)
	}
	if !routeOK {
		r.logger.Info("restoring ip rule/route")
		if err := r.route.DetectGateway(); err != nil {
			r.logger.Error("detecting gateway", "err", err)
			return
		}
		if err := r.route.Setup(); err != nil {
			r.logger.Error("restoring route", "err", err)
		}
	}

	// Safety net: re-scan processes in case any exec events were missed
	// (e.g. netlink buffer overflow under heavy fork load).
	if err := r.procmon.ScanExisting(); err != nil {
		r.logger.Warn("periodic process scan", "err", err)
	}
}
