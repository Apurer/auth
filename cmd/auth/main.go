package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Apurer/auth/internal/auth"
	"github.com/Apurer/auth/internal/config"
	"github.com/Apurer/auth/internal/directory"
	"github.com/Apurer/auth/internal/transport"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func snapshot(path string, m *directory.Metrics) (*auth.Snapshot, error) {
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	d, err := directory.New(c.Directory, c.Limits.MaxGroups, m)
	if err != nil {
		return nil, err
	}
	return &auth.Snapshot{Config: c, Directory: d}, nil
}

func run(path string, logger *slog.Logger) error {
	registry := prometheus.NewRegistry()
	dm := directory.NewMetrics(registry)
	snap, err := snapshot(path, dm)
	if err != nil {
		return err
	}
	if snap.Config.Directory.TLS.InsecureSkipVerify {
		logger.Warn("AD server certificate verification is disabled by configuration")
	}
	svc := auth.New(snap, registry, logger)
	server, err := transport.Server(snap.Config)
	if err != nil {
		return err
	}
	listener, err := transport.Listen(snap.Config.Listen)
	if err != nil {
		return errors.New("cannot create gRPC listener")
	}
	defer listener.Close()
	adminListener, err := net.Listen("tcp", snap.Config.AdminListen)
	if err != nil {
		return errors.New("cannot create admin listener")
	}
	defer adminListener.Close()
	authv3.RegisterAuthorizationServer(server, svc)
	var healthy atomic.Pointer[auth.Snapshot]
	probe := func() {
		current := svc.Snapshot()
		ctx, cancel := context.WithTimeout(context.Background(), current.Config.Limits.Timeout)
		defer cancel()
		if current.Directory.Probe(ctx) == nil {
			healthy.Store(current)
		} else {
			healthy.Store(nil)
		}
	}
	probe()
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if healthy.Load() != svc.Snapshot() {
			http.Error(w, "directory unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	admin := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	serveErr := make(chan error, 2)
	go func() { serveErr <- server.Serve(listener) }()
	go func() { serveErr <- admin.Serve(adminListener) }()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	logger.Info("authentication service started", "config_version", snap.Config.Version)
	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() { server.GracefulStop(); close(done) }()
			select {
			case <-done:
			case <-shutdown.Done():
				server.Stop()
			}
			admin.Shutdown(shutdown)
			return nil
		case <-serveErr:
			server.Stop()
			admin.Close()
			return errors.New("listener stopped unexpectedly")
		case <-ticker.C:
			probe()
		case <-reload:
			next, err := snapshot(path, dm)
			if err == nil {
				check, cancel := context.WithTimeout(ctx, next.Config.Limits.Timeout)
				err = next.Directory.Probe(check)
				cancel()
			}
			if err == nil {
				err = svc.Reload(next)
			}
			if err != nil {
				logger.Error("configuration reload rejected; retaining previous configuration")
				continue
			}
			healthy.Store(next)
			if next.Config.Directory.TLS.InsecureSkipVerify {
				logger.Warn("AD server certificate verification is disabled by configuration")
			}
			logger.Info("configuration reloaded", "config_version", next.Config.Version)
		}
	}
}

func main() {
	path := flag.String("config", "/etc/envoy-ad-auth/config.yaml", "configuration path")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(*path, logger); err != nil {
		logger.Error("startup failed", "reason", err.Error())
		os.Exit(1)
	}
}
