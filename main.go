package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

func main() {
	configPath := flag.String("config", "byway.toml", "path to config file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	if os.Getuid() != 0 {
		logger.Error("byway must run as root")
		os.Exit(1)
	}

	daemon := NewDaemon(*configPath, logger)
	defer daemon.Shutdown()

	ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM)
	defer cancel()

	if err := daemon.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("daemon error", "err", err)
		os.Exit(1)
	}
}
