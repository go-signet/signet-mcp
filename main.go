// Command signet-mcp is the official MCP server for Signet, exposing OAuth
// diagnostics and flow-testing tools over stdio or streamable HTTP.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/appleboy/graceful"

	"github.com/go-signet/signet-mcp/internal/config"
	"github.com/go-signet/signet-mcp/internal/server"
)

func main() {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "signet-mcp:", err)
		os.Exit(2)
	}
	if cfg.ShowVersion {
		fmt.Println("signet-mcp version", server.Version)
		return
	}
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "signet-mcp:", err)
		os.Exit(1)
	}
}

func run(cfg *config.Config) error {
	log := newLogger(cfg)
	srv, err := server.New(cfg, log)
	if err != nil {
		return err
	}

	m := graceful.NewManager(
		graceful.WithShutdownTimeout(cfg.ShutdownTimeout),
		graceful.WithLogger(graceful.NewSlogLogger(graceful.WithSlog(log))),
	)

	switch cfg.Transport {
	case config.TransportStdio:
		m.AddRunningJob(srv.RunStdio)
	case config.TransportHTTP:
		httpSrv, err := srv.HTTPServer(context.Background())
		if err != nil {
			return err
		}
		m.AddRunningJob(func(ctx context.Context) error {
			errCh := make(chan error, 1)
			go func() { errCh <- httpSrv.ListenAndServe() }()
			select {
			case <-ctx.Done():
				return nil
			case err := <-errCh:
				if errors.Is(err, http.ErrServerClosed) {
					return nil
				}
				return err
			}
		})
		m.AddShutdownJob(func() error {
			// Drain in-flight requests within the manager's shutdown window.
			ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
			defer cancel()
			return httpSrv.Shutdown(ctx)
		})
	}

	<-m.Done()
	if errs := m.Errors(); len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// newLogger builds the structured logger. In stdio mode logs must go to
// stderr — stdout carries the MCP protocol.
func newLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if cfg.LogJSON {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(h)
}
