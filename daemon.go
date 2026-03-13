package main

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"
)

// Daemon orchestrates all byway components.
type Daemon struct {
	configPath string
	config     *Config
	nft        *NFT
	route      *Route
	procmon    *ProcMon
	reconciler *Reconciler
	logger     *slog.Logger
}

func NewDaemon(configPath string, logger *slog.Logger) *Daemon {
	return &Daemon{
		configPath: configPath,
		logger:     logger,
	}
}

// Run starts the daemon and blocks until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	cfg, err := LoadConfig(d.configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	d.config = cfg

	// Create cgroup.
	cgroupID, err := CreateCgroup()
	if err != nil {
		return fmt.Errorf("creating cgroup: %w", err)
	}
	d.logger.Info("cgroup created", "path", cgroupPath, "id", cgroupID)

	// Setup nftables — adopt existing table if valid (crash recovery),
	// otherwise create fresh.
	d.nft = NewNFT(d.logger)
	if !d.nft.Adopt() {
		if err := d.nft.Setup(cgroupID, fwMark); err != nil {
			return fmt.Errorf("nftables setup: %w", err)
		}
	}
	d.logger.Info("nftables configured", "fwmark", fmt.Sprintf("0x%x", fwMark))

	// Setup routing.
	d.route = NewRoute(cfg.Interface, d.logger)
	if err := d.route.DetectGateway(); err != nil {
		return fmt.Errorf("detecting gateway: %w", err)
	}
	if err := d.route.Setup(); err != nil {
		return fmt.Errorf("route setup: %w", err)
	}
	mode := "dedicated"
	if d.route.IsSharedInterface() {
		mode = "shared"
		d.logger.Warn("interface is shared with system default route — VPN may flush rules periodically, reconciler will restore them")
	}
	d.logger.Info("routing configured",
		"iface", cfg.Interface,
		"gateway", d.route.Gateway(),
		"table", routeTable,
		"mode", mode,
	)

	// Create process monitor (scan happens inside Run, after netlink subscription).
	d.procmon = NewProcMon(cfg.Apps, d.logger)

	// Create reconciler.
	d.reconciler = NewReconciler(d.nft, d.route, d.procmon, cgroupID, fwMark, d.logger)

	d.logger.Info("byway started",
		"iface", cfg.Interface,
		"apps", len(cfg.Apps),
		"reconcile", cfg.Reconcile.Duration,
	)

	// Run three concurrent loops.
	g, gctx := errgroup.WithContext(ctx)

	// Config watcher.
	g.Go(func() error {
		configCh := WatchConfig(gctx, d.configPath, d.logger)
		for {
			select {
			case <-gctx.Done():
				return gctx.Err()
			case newCfg := <-configCh:
				if newCfg == nil {
					continue
				}
				d.handleConfigChange(newCfg)
			}
		}
	})

	// Process monitor.
	g.Go(func() error {
		return d.procmon.Run(gctx)
	})

	// Reconciler (skip if interval is zero).
	if cfg.Reconcile.Duration > 0 {
		g.Go(func() error {
			return d.reconciler.Run(gctx, cfg.Reconcile.Duration)
		})
	}

	// Route monitor — react immediately to route changes instead of
	// waiting for the next reconcile tick. Especially important in
	// shared-interface mode where the VPN may flush routes.
	g.Go(func() error {
		rm := NewRouteMonitor(d.route.Link(), d.reconciler, d.logger)
		return rm.Run(gctx)
	})

	return g.Wait()
}

// handleConfigChange is called serially from the config watcher goroutine.
func (d *Daemon) handleConfigChange(newCfg *Config) {
	oldCfg := d.config

	// Update app list.
	d.procmon.UpdateApps(newCfg.Apps)
	if err := d.procmon.ScanExisting(); err != nil {
		d.logger.Warn("scanning existing processes after config change", "err", err)
	}
	d.logger.Info("app list updated", "apps", len(newCfg.Apps))

	// Interface change requires route teardown/setup.
	if newCfg.Interface != oldCfg.Interface {
		d.logger.Info("interface changed", "old", oldCfg.Interface, "new", newCfg.Interface)
		if err := d.route.UpdateInterface(newCfg.Interface); err != nil {
			d.logger.Error("updating interface", "err", err)
		} else {
			d.logger.Info("routing updated", "iface", newCfg.Interface, "gateway", d.route.Gateway())
		}
	}

	// Reconcile interval change.
	if newCfg.Reconcile.Duration != oldCfg.Reconcile.Duration && d.reconciler != nil {
		d.reconciler.UpdateInterval(newCfg.Reconcile.Duration)
	}

	d.config = newCfg
}

// Shutdown tears down all infrastructure in reverse order.
func (d *Daemon) Shutdown() {
	d.logger.Info("shutting down")

	if d.nft != nil {
		if err := d.nft.Teardown(); err != nil {
			d.logger.Warn("nftables teardown", "err", err)
		}
	}

	if d.route != nil {
		d.route.Teardown()
	}

	if err := DestroyCgroup(d.logger); err != nil {
		d.logger.Warn("cgroup teardown", "err", err)
	}

	d.logger.Info("cleanup complete")
}
