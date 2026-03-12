package main

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fsnotify/fsnotify"
)

type Config struct {
	Interface string   `toml:"interface"`
	Reconcile Duration `toml:"reconcile"`
	Apps      []string `toml:"apps"`
}

// Duration wraps time.Duration for TOML unmarshaling.
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}

func LoadConfig(path string) (*Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if cfg.Interface == "" {
		return nil, fmt.Errorf("interface is required")
	}
	if len(cfg.Apps) == 0 {
		return nil, fmt.Errorf("at least one app is required")
	}
	for i, app := range cfg.Apps {
		if app == "" {
			return nil, fmt.Errorf("apps[%d]: path is required", i)
		}
		if !filepath.IsAbs(app) {
			return nil, fmt.Errorf("apps[%d]: path must be absolute: %s", i, app)
		}
		// Resolve symlinks so paths match /proc/PID/exe (which returns the real path).
		resolved, err := filepath.EvalSymlinks(app)
		if err != nil {
			return nil, fmt.Errorf("apps[%d]: resolving path %s: %w", i, app, err)
		}
		cfg.Apps[i] = resolved
	}
	if cfg.Reconcile.Duration == 0 {
		cfg.Reconcile.Duration = 5 * time.Second
	}
	return &cfg, nil
}

// WatchConfig watches the config file for changes and sends new configs on the returned channel.
// The channel is never closed; it becomes unreachable when ctx is cancelled.
func WatchConfig(ctx context.Context, path string, logger *slog.Logger) <-chan *Config {
	ch := make(chan *Config, 1)

	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			logger.Error("creating config watcher", "err", err)
			return
		}
		defer watcher.Close()

		// Watch the directory (not the file) to handle editors that
		// write to a temp file and rename.
		dir := filepath.Dir(path)
		if err := watcher.Add(dir); err != nil {
			logger.Error("watching config directory", "dir", dir, "err", err)
			return
		}

		base := filepath.Base(path)
		var debounce *time.Timer

		for {
			select {
			case <-ctx.Done():
				if debounce != nil {
					debounce.Stop()
				}
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if filepath.Base(event.Name) != base {
					continue
				}
				if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) {
					continue
				}
				if debounce != nil {
					debounce.Stop()
				}
				debounce = time.AfterFunc(100*time.Millisecond, func() {
					if ctx.Err() != nil {
						return
					}
					cfg, err := LoadConfig(path)
					if err != nil {
						logger.Error("reloading config", "err", err)
						return
					}
					logger.Info("config reloaded")
					select {
					case ch <- cfg:
					default:
					}
				})
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logger.Warn("config watcher error", "err", err)
			}
		}
	}()

	return ch
}
